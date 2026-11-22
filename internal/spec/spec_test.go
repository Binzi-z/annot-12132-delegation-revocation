package spec_test

import (
	"path/filepath"
	"testing"

	"revauth/internal/engine"
	"revauth/internal/model"
	"revauth/internal/spec"
	"revauth/internal/testkit"
)

// fixture 持有驱动一条真实委派路径所需的全部句柄。
type fixture struct {
	dir  string
	now  int64
	eng  *engine.Engine
	a, b *testkit.Issuer
	cert model.AdmissionCertificate
}

func setup(t *testing.T) *fixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "node")
	var now int64 = 1_000_000
	clock := func() int64 { return now }
	eng, err := engine.Open(dir, engine.WithClock(clock))
	if err != nil {
		t.Fatal(err)
	}
	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testkit.NewIssuer(testkit.OrgB)
	if err != nil {
		t.Fatal(err)
	}
	mustEmit(t, eng, a.ID, model.EvKeyRotated, model.KeyRotatedPayload{NewGeneration: a.Gen, PublicKey: a.Pub})
	mustEmit(t, eng, b.ID, model.EvKeyRotated, model.KeyRotatedPayload{NewGeneration: b.Gen, PublicKey: b.Pub})
	mustEmit(t, eng, a.ID, model.EvHeartbeat, model.HeartbeatPayload{})
	mustEmit(t, eng, b.ID, model.EvHeartbeat, model.HeartbeatPayload{})

	path := []model.DelegationEdge{
		testkit.Edge(a, "alice", "dave", now-10, now+1000),
		testkit.Edge(b, "dave", "bob", now-10, now+1000),
	}
	return &fixture{dir: dir, now: now, eng: eng, a: a, b: b, cert: testkit.Cert("bob", path)}
}

// mustEmit 正常事件发出；若签发者已被隔离则跳过（隔离后任何写入都应失败，
// 这是协议的正确行为，状态机一侧保持 quarantined 吸收态）。
func mustEmit(t *testing.T, eng *engine.Engine, org model.OrgID, kind model.EventKind, p any) {
	t.Helper()
	if eng.IsQuarantined(org) {
		return
	}
	if _, err := eng.Emit(org, kind, p); err != nil {
		t.Fatalf("emit %s: %v", kind, err)
	}
}

// applyTrigger 把参考状态机的触发映射为真实引擎操作。
func (f *fixture) applyTrigger(t *testing.T, tr spec.Trigger) {
	t.Helper()
	now := f.now
	switch tr {
	case spec.TrigKeyRotation:
		rot, _, err := f.a.Rotate()
		if err != nil {
			t.Fatal(err)
		}
		mustEmit(t, f.eng, f.a.ID, model.EvKeyRotated, rot)

	case spec.TrigMemberExit:
		mustEmit(t, f.eng, f.a.ID, model.EvMemberExited,
			model.MemberExitedPayload{Member: "alice"})

	case spec.TrigReauthorize:
		// 若因退出/换主失效，先消除前置条件再用当前代际重签整条路径。
		mustEmit(t, f.eng, f.a.ID, model.EvMemberRejoined,
			model.MemberRejoinedPayload{Member: "alice"})
		path := []model.DelegationEdge{
			testkit.Edge(f.a, "alice", "dave", now-10, now+1000),
			testkit.Edge(f.b, "dave", "bob", now-10, now+1000),
		}
		f.cert = testkit.Cert("bob", path)

	case spec.TrigExpire:
		path := []model.DelegationEdge{
			testkit.Edge(f.a, "alice", "dave", now-100, now-1),
			testkit.Edge(f.b, "dave", "bob", now-100, now-1),
		}
		f.cert = testkit.Cert("bob", path)

	case spec.TrigEmergencyBan:
		mustEmit(t, f.eng, f.a.ID, model.EvEmergencyBan, model.EmergencyBanPayload{
			Tenant: testkit.Tenant, Resource: testkit.Resource, Subject: "bob",
		})

	case spec.TrigBanLift:
		mustEmit(t, f.eng, f.a.ID, model.EvBanLift, model.BanLiftedPayload{
			Tenant: testkit.Tenant, Resource: testkit.Resource, Subject: "bob",
		})
	case spec.TrigCompact:
		if f.eng.IsQuarantined(f.a.ID) {
			break // 隔离分区不可写，跳过压缩；状态机中 compact 为恒等转移
		}
		if _, err := f.eng.Compact(); err != nil {
			t.Fatalf("compact: %v", err)
		}

	case spec.TrigRestart:
		eng2, err := engine.Open(f.dir, engine.WithClock(func() int64 { return f.now }))
		if err != nil {
			t.Fatalf("restart: %v", err)
		}
		f.eng = eng2

	case spec.TrigIssuerFault:
		if err := f.eng.Quarantine(f.a.ID); err != nil {
			t.Fatal(err)
		}
	}
}

// expectAllow 依据参考状态机状态给出真实引擎应有的放行预期。
func expectAllow(state model.PathState) bool {
	return state == model.PathActive
}

// TestInterleavingsMatchStateMachine 枚举全部交错，逐一比对规范与引擎决策。
func TestInterleavingsMatchStateMachine(t *testing.T) {
	all := spec.Enumerate()
	if len(all) < 100 {
		t.Fatalf("expected a large enumerated set, got %d", len(all))
	}
	for _, il := range all {
		il := il
		t.Run(il.Name, func(t *testing.T) {
			f := setup(t)
			fsm := spec.NewPathFSM()
			for _, tr := range il.Triggers {
				wantState, _ := fsm.Step(tr)
				f.applyTrigger(t, tr)

				d := f.eng.EvaluateAny(f.cert, model.AccessRead)
				want := expectAllow(wantState)
				if d.Allowed != want {
					t.Fatalf("trigger=%s state=%s mismatch: engine allowed=%v reason=%s want=%v",
						tr, wantState, d.Allowed, d.Reason, want)
				}
			}
		})
	}
}

// TestBanSurvivesAllInterleavings 聚焦粘性不变量：任何交错下，禁用未解除前
// 压缩与重启都不得恢复访问。
func TestBanSurvivesAllInterleavings(t *testing.T) {
	for _, il := range spec.Enumerate() {
		il := il
		t.Run(il.Name+"_ban", func(t *testing.T) {
			f := setup(t)
			banned := false
			for _, tr := range il.Triggers {
				f.applyTrigger(t, tr)
				switch tr {
				case spec.TrigEmergencyBan:
					banned = true
				case spec.TrigBanLift:
					banned = false
				}
				d := f.eng.EvaluateAny(f.cert, model.AccessRead)
				if banned && d.Allowed {
					t.Fatalf("ban violated after trigger=%s reason=%s", tr, d.Reason)
				}
			}
		})
	}
}
