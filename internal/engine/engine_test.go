package engine_test

import (
	"path/filepath"
	"testing"
	"time"

	"revauth/internal/engine"
	"revauth/internal/model"
	"revauth/internal/testkit"
)

// clock 可控时钟，advance 推进测试时间以制造分区/过期。
type clock struct{ t int64 }

func newClock(start int64) *clock { return &clock{t: start} }
func (c *clock) get() int64      { return c.t }
func (c *clock) advance(d time.Duration) {
	c.t += int64(d.Seconds())
}

const fixedNow int64 = 1_000_000

// helper：在临时目录打开带可控时钟的引擎，并引导两个签发者创始代际+心跳。
func newEngine(t *testing.T) (*engine.Engine, *testkit.Issuer, *testkit.Issuer, *clock) {
	t.Helper()
	dir := t.TempDir()
	c := newClock(fixedNow)
	eng, err := engine.Open(filepath.Join(dir, "node"), engine.WithClock(c.get))
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testkit.NewIssuer(testkit.OrgB)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, eng, a, c)
	bootstrap(t, eng, b, c)
	return eng, a, b, c
}

func bootstrap(t *testing.T, eng *engine.Engine, iss *testkit.Issuer, c *clock) {
	t.Helper()
	if _, err := eng.Emit(iss.ID, model.EvKeyRotated, model.KeyRotatedPayload{
		NewGeneration: iss.Gen, PublicKey: iss.Pub,
	}); err != nil {
		t.Fatalf("bootstrap key: %v", err)
	}
	if _, err := eng.Emit(iss.ID, model.EvHeartbeat, model.HeartbeatPayload{}); err != nil {
		t.Fatalf("bootstrap heartbeat: %v", err)
	}
}

// TestIndependentPaths 核心需求：一条路径被撤销，另一条独立路径继续可用。
func TestIndependentPaths(t *testing.T) {
	eng, a, b, c := newEngine(t)
	now := c.get()
	// 路径 P1：org-a 内 alice -> bob；路径 P2：跨组织 carol(org-a) -> dave(org-b) -> bob。
	p1 := []model.DelegationEdge{
		testkit.Edge(a, "alice", "bob", now-10, now+100),
	}
	p2 := []model.DelegationEdge{
		testkit.Edge(a, "carol", "dave", now-10, now+100),
		testkit.Edge(b, "dave", "bob", now-10, now+100),
	}
	cert := testkit.Cert("bob", p1, p2)

	if d := eng.EvaluateAny(cert, model.AccessRead); !d.Allowed {
		t.Fatalf("initial access should be allowed, reason=%s", d.Reason)
	}

	// org-a 换主：含 org-a 旧代际边的路径全部失效（代际撤销）。
	rot, _, err := a.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Emit(testkit.OrgA, model.EvKeyRotated, rot); err != nil {
		t.Fatal(err)
	}
	if d := eng.EvaluateAny(cert, model.AccessRead); d.Allowed {
		t.Fatalf("stale-generation paths must be revoked")
	} else if d.Reason != model.ReasonDeniedNoValidPath {
		t.Fatalf("unexpected reason %s", d.Reason)
	}

	// 用新代际重新签发仅 P2（独立路径），P2 恢复，P1 仍撤销。
	newP2 := []model.DelegationEdge{
		testkit.Edge(a, "carol", "dave", now-10, now+100),
		testkit.Edge(b, "dave", "bob", now-10, now+100),
	}
	cert2 := testkit.Cert("bob", p1, newP2)
	if d := eng.EvaluateAny(cert2, model.AccessRead); !d.Allowed {
		t.Fatalf("re-authorized independent path should be allowed, reason=%s", d.Reason)
	}
}

// TestMemberExitRevokesPath 成员退出撤销含该成员的路径，独立路径不受影响。
func TestMemberExitRevokesPath(t *testing.T) {
	eng, a, b, c := newEngine(t)
	now := c.get()
	p1 := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", now-10, now+100)}
	p2 := []model.DelegationEdge{
		testkit.Edge(a, "carol", "dave", now-10, now+100),
		testkit.Edge(b, "dave", "bob", now-10, now+100),
	}
	cert := testkit.Cert("bob", p1, p2)

	if _, err := eng.Emit(testkit.OrgA, model.EvMemberExited,
		model.MemberExitedPayload{Member: "alice"}); err != nil {
		t.Fatal(err)
	}
	d := eng.EvaluateAny(cert, model.AccessRead)
	if !d.Allowed {
		t.Fatalf("independent path P2 must stay available, reason=%s", d.Reason)
	}
	var foundExit bool
	for _, ck := range d.Checks {
		if ck.Reason == model.ReasonDeniedMemberExited {
			foundExit = true
		}
	}
	if !foundExit {
		t.Fatal("expected an explicit member-exit denial among checks")
	}
}

// TestEmergencyBanSticky 紧急禁用不能被压缩、重启或换链清除。
func TestEmergencyBanSticky(t *testing.T) {
	dir := t.TempDir()
	c := newClock(fixedNow)
	eng, err := engine.Open(filepath.Join(dir, "node"), engine.WithClock(c.get))
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
	bootstrap(t, eng, a, c)
	bootstrap(t, eng, b, c)
	now := c.get()
	p1 := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", now-10, now+100)}
	cert := testkit.Cert("bob", p1)

	ban := model.EmergencyBanPayload{Tenant: testkit.Tenant, Resource: testkit.Resource, Subject: "bob"}
	if _, err := eng.Emit(testkit.OrgA, model.EvEmergencyBan, ban); err != nil {
		t.Fatal(err)
	}
	if d := eng.EvaluateAny(cert, model.AccessRead); d.Allowed || d.Reason != model.ReasonDeniedEmergencyBan {
		t.Fatalf("ban must deny, got allowed=%v reason=%s", d.Allowed, d.Reason)
	}

	// 压缩：禁用证据必须进入快照。
	if _, err := eng.Compact(); err != nil {
		t.Fatalf("compact: %v", err)
	}
	// 重启恢复：重新打开引擎，重放压缩后日志。
	eng2, err := engine.Open(filepath.Join(dir, "node"), engine.WithClock(c.get))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	// 换一条全新委派路径（换链），禁用仍须生效。
	rot, _, err := a.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng2.Emit(testkit.OrgA, model.EvKeyRotated, rot); err != nil {
		t.Fatal(err)
	}
	newPath := []model.DelegationEdge{testkit.Edge(a, "zoe", "bob", now-10, now+100)}
	cert2 := testkit.Cert("bob", newPath)
	d := eng2.EvaluateAny(cert2, model.AccessRead)
	if d.Allowed || d.Reason != model.ReasonDeniedEmergencyBan || d.BanEvidence == nil {
		t.Fatalf("ban must survive compaction+restart+path switch, got %+v", d)
	}

	// 显式解除后才可恢复。
	if _, err := eng2.Emit(testkit.OrgA, model.EvBanLift, model.BanLiftedPayload{
		Tenant: testkit.Tenant, Resource: testkit.Resource, Subject: "bob",
	}); err != nil {
		t.Fatal(err)
	}
	if d := eng2.EvaluateAny(cert2, model.AccessRead); !d.Allowed {
		t.Fatalf("access should restore after explicit lift, reason=%s", d.Reason)
	}
}

// TestPartitionSemantics 明确签发者分区时各类访问的正确语义。
func TestPartitionSemantics(t *testing.T) {
	eng, a, b, c := newEngine(t)
	now := c.get()
	path := []model.DelegationEdge{
		testkit.Edge(a, "alice", "dave", now-10, now+1000),
		testkit.Edge(b, "dave", "bob", now-10, now+1000),
	}
	cert := testkit.Cert("bob", path)

	// 推进时间超过宽限期且无新心跳 -> org-a/org-b 陈旧。
	c.advance(60 * time.Second)
	if d := eng.EvaluateAny(cert, model.AccessWrite); d.Allowed || d.Reason != model.ReasonDeniedFailClosed {
		t.Fatalf("write under partition must fail-closed, got %s", d.Reason)
	}
	if d := eng.EvaluateAny(cert, model.AccessEscalate); d.Allowed || d.Reason != model.ReasonDeniedFailClosed {
		t.Fatalf("escalate under partition must fail-closed, got %s", d.Reason)
	}
	if d := eng.EvaluateAny(cert, model.AccessRead); d.Allowed || d.Reason != model.ReasonDeniedReadGraceExpired {
		t.Fatalf("read past grace must be denied with grace reason, got %s", d.Reason)
	}

	// 恢复心跳（时钟已推进，新心跳时间戳反映“当下”）后全部放行。
	if _, err := eng.Emit(testkit.OrgA, model.EvHeartbeat, model.HeartbeatPayload{}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Emit(testkit.OrgB, model.EvHeartbeat, model.HeartbeatPayload{}); err != nil {
		t.Fatal(err)
	}
	if d := eng.EvaluateAny(cert, model.AccessWrite); !d.Allowed {
		t.Fatalf("write after recovery must pass, reason=%s", d.Reason)
	}
}

// TestDegradedReadWithinGrace 宽限期内陈旧读降级放行并标记 degraded。
func TestDegradedReadWithinGrace(t *testing.T) {
	eng, a, b, c := newEngine(t)
	now := c.get()
	path := []model.DelegationEdge{
		testkit.Edge(a, "alice", "dave", now-10, now+1000),
		testkit.Edge(b, "dave", "bob", now-10, now+1000),
	}
	cert := testkit.Cert("bob", path)
	c.advance(10 * time.Second) // 小于 30s 宽限
	d := eng.EvaluateAny(cert, model.AccessRead)
	if !d.Allowed || !d.Degraded {
		t.Fatalf("read within grace should be allowed+degraded, got allowed=%v degraded=%v", d.Allowed, d.Degraded)
	}
	// 写仍 fail-closed。
	if w := eng.EvaluateAny(cert, model.AccessWrite); w.Allowed {
		t.Fatal("write must remain fail-closed during partition")
	}
}

// TestExpiredPath 过期路径拒绝，重新授权后恢复。
func TestExpiredPath(t *testing.T) {
	eng, a, _, c := newEngine(t)
	now := c.get()
	old := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", now-100, now-1)}
	cert := testkit.Cert("bob", old)
	if d := eng.EvaluateAny(cert, model.AccessRead); d.Allowed || d.Reason != model.ReasonDeniedNoValidPath {
		t.Fatalf("expired path must be denied, got %s", d.Reason)
	}
	fresh := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", now-10, now+100)}
	if d := eng.EvaluateAny(testkit.Cert("bob", fresh), model.AccessRead); !d.Allowed {
		t.Fatalf("re-issued fresh path must be allowed, reason=%s", d.Reason)
	}
}

// TestWatermarkMigration 水位随快照迁移，重启后重复事件被幂等拒绝。
func TestWatermarkMigration(t *testing.T) {
	dir := t.TempDir()
	c := newClock(fixedNow)
	eng, err := engine.Open(filepath.Join(dir, "node"), engine.WithClock(c.get))
	if err != nil {
		t.Fatal(err)
	}
	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap(t, eng, a, c)
	exitEv, err := eng.Emit(testkit.OrgA, model.EvMemberExited,
		model.MemberExitedPayload{Member: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	wmBefore := eng.Watermark(testkit.OrgA)
	if _, err := eng.Compact(); err != nil {
		t.Fatal(err)
	}
	eng2, err := engine.Open(filepath.Join(dir, "node"), engine.WithClock(c.get))
	if err != nil {
		t.Fatal(err)
	}
	if wm := eng2.Watermark(testkit.OrgA); wm < wmBefore {
		t.Fatalf("watermark regressed after migration: %d -> %d", wmBefore, wm)
	}
	// 重放压缩前的旧事件：必须被幂等拒绝而非重新应用。
	if err := eng2.Ingest(*exitEv); err != engine.ErrAlreadyApplied {
		t.Fatalf("expected ErrAlreadyApplied, got %v", err)
	}
}

// TestFaultIsolation 一个签发者链损坏被隔离，另一签发者继续服务。
func TestFaultIsolation(t *testing.T) {
	eng, a, b, c := newEngine(t)
	now := c.get()
	// 直接隔离 org-a（等价于节点检测到该签发者哈希链损坏后的处置动作）。
	if err := eng.Quarantine(testkit.OrgA); err != nil {
		t.Fatal(err)
	}
	pathB := []model.DelegationEdge{testkit.Edge(b, "carol", "bob", now-10, now+100)}
	certB := testkit.Cert("bob", pathB)
	if d := eng.EvaluateAny(certB, model.AccessRead); !d.Allowed {
		t.Fatalf("healthy org-b path must survive org-a fault, reason=%s", d.Reason)
	}
	pathA := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", now-10, now+100)}
	if d := eng.EvaluateAny(testkit.Cert("bob", pathA), model.AccessRead); d.Allowed {
		t.Fatal("quarantined org-a path must be denied")
	}
}
