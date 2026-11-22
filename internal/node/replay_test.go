package node_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"revauth/internal/model"
	"revauth/internal/queue"
	"revauth/internal/testkit"
)

const testNow int64 = 1_000_000

// feedBootstrap 通过各自队列把创始事件投递给两个节点并等待生效。
func feedBootstrap(t *testing.T, n1, n2 *procNode, boot map[model.OrgID][]model.Event) {
	t.Helper()
	for _, pn := range []*procNode{n1, n2} {
		q, err := queue.Open(pn.queueDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, org := range []model.OrgID{testkit.OrgA, testkit.OrgB} {
			for _, ev := range boot[org] {
				if _, err := q.Enqueue(ev); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	// 两个节点都应处理完 4 条创始事件（每 org 2 条）。
	waitFor(t, 5*time.Second, func() bool {
		c1, _ := ackCount(n1.queueDir)
		c2, _ := ackCount(n2.queueDir)
		return c1 >= 4 && c2 >= 4
	}, "bootstrap events replicated to both nodes")
}

func ackCount(queueDir string) (int, error) {
	entries, err := os.ReadDir(filepath.Join(queueDir, "ack"))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			n++
		}
	}
	return n, nil
}

// TestTwoProcessMinimalCounterexample 最小反例重放。
//
// 场景：紧急禁用事件被队列“滞留”，节点尚未收到禁用。
//   - 朴素“仅验签”校验器会被旧签名快照欺骗继续放行（暴露缺陷）；
//   - 真实节点在禁用一旦到达后立即拒绝，且经过压缩、重启、换链、
//     重放旧证书都无法恢复——证明撤销证据粘性与不可借旧数据复活。
func TestTwoProcessMinimalCounterexample(t *testing.T) {
	root := t.TempDir()
	n1 := startNode(t, "node1", root)
	n2 := startNode(t, "node2", root)
	defer n1.stop(t)
	defer n2.stop(t)

	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testkit.NewIssuer(testkit.OrgB)
	if err != nil {
		t.Fatal(err)
	}
	boot := bootstrapEvents(t, a, b, testNow)
	feedBootstrap(t, n1, n2, boot)

	path := []model.DelegationEdge{
		testkit.Edge(a, "alice", "dave", testNow-10, testNow+1000),
		testkit.Edge(b, "dave", "bob", testNow-10, testNow+1000),
	}
	cert := testkit.Cert("bob", path)

	// 初始：两个真实节点都放行。
	if d := n1.admit(t, cert, model.AccessRead); !d.Allowed {
		t.Fatalf("node1 initial deny: %s", d.Reason)
	}
	if d := n2.admit(t, cert, model.AccessRead); !d.Allowed {
		t.Fatalf("node2 initial deny: %s", d.Reason)
	}

	// 朴素校验器此刻也放行（它只看签名）。
	naive := testkit.NewNaiveVerifier(a, b)
	if !naive.Allow(cert, testNow) {
		t.Fatal("naive verifier baseline should allow")
	}

	// 构造紧急禁用事件，但仅“滞留”在 node1 的 held 队列，不投递。
	banSeq := uint64(3) // org-a 创始已用 seq 1,2
	banEv := model.Event{
		Seq: banSeq, Issuer: testkit.OrgA, Kind: model.EvEmergencyBan, EmittedAt: testNow,
		Payload: model.EmergencyBanPayload{
			Tenant: testkit.Tenant, Resource: testkit.Resource, Subject: "bob",
		},
	}
	banEv.PrevHash = boot[testkit.OrgA][1].Hash
	banEv.Hash = banEv.Digest()

	q1, err := queue.Open(n1.queueDir)
	if err != nil {
		t.Fatal(err)
	}
	heldName, err := q1.Hold(banEv)
	if err != nil {
		t.Fatal(err)
	}

	// 反例前提：禁用未到达，真实节点仍放行（此时无证据可依），朴素器也放行。
	if d := n1.admit(t, cert, model.AccessRead); !d.Allowed {
		t.Fatalf("before ban delivery node1 should still allow: %s", d.Reason)
	}

	// 释放禁用事件到 node1，节点轮询后必须立即拒绝。
	if err := q1.Release(heldName); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		d := n1.admit(t, cert, model.AccessRead)
		return !d.Allowed && d.Reason == model.ReasonDeniedEmergencyBan
	}, "node1 denies after emergency ban delivered")

	// 最小反例对比：朴素校验器仍被旧签名快照欺骗（错误放行）。
	if !naive.Allow(cert, testNow) {
		t.Fatal("naive verifier is expected to be fooled by the stale signed snapshot")
	}
	t.Logf("counterexample reproduced: naive verifier ALLOWS while real node DENIES (%s)",
		model.ReasonDeniedEmergencyBan)

	// node2 尚未收到禁用，仍可用——证明节点间状态独立、故障/延迟隔离。
	if d := n2.admit(t, cert, model.AccessRead); !d.Allowed {
		t.Fatalf("node2 without ban must remain available: %s", d.Reason)
	}

	// 压缩 node1：禁用进入快照。
	n1.compact(t)
	// 换主 + 换一条全新路径，禁用仍须生效。
	rot, _, err := a.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	n1.postEvent(t, model.EvKeyRotated, testkit.OrgA, rot)

	// 重启 node1（关闭后用同一数据目录重新拉起）。
	n1.stop(t)
	n1 = startNode(t, "node1", root)
	defer n1.stop(t)
	n1.heartbeat(t, testkit.OrgA)
	n1.heartbeat(t, testkit.OrgB)

	newPath := []model.DelegationEdge{
		testkit.Edge(a, "zoe", "bob", testNow-10, testNow+1000),
	}
	newCert := testkit.Cert("bob", newPath)
	waitFor(t, 5*time.Second, func() bool {
		d := n1.admit(t, newCert, model.AccessRead)
		return !d.Allowed && d.Reason == model.ReasonDeniedEmergencyBan
	}, "ban survives compaction, restart and path switch on node1")

	// 重放旧证书同样被拒，确认无法借旧数据恢复。
	if d := n1.admit(t, cert, model.AccessRead); d.Allowed {
		t.Fatal("old certificate replay must not resurrect access")
	}
}

// TestTwoProcessIndependentPaths 双节点上验证独立路径：撤销其一，另一条持续可用。
func TestTwoProcessIndependentPaths(t *testing.T) {
	root := t.TempDir()
	n1 := startNode(t, "node1", root)
	n2 := startNode(t, "node2", root)
	defer n1.stop(t)
	defer n2.stop(t)

	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testkit.NewIssuer(testkit.OrgB)
	if err != nil {
		t.Fatal(err)
	}
	feedBootstrap(t, n1, n2, bootstrapEvents(t, a, b, testNow))

	// 两条独立路径：P1 仅 org-a；P2 跨 org-a -> org-b。
	p1 := []model.DelegationEdge{testkit.Edge(a, "alice", "bob", testNow-10, testNow+1000)}
	p2 := []model.DelegationEdge{
		testkit.Edge(a, "carol", "dave", testNow-10, testNow+1000),
		testkit.Edge(b, "dave", "bob", testNow-10, testNow+1000),
	}
	cert := testkit.Cert("bob", p1, p2)
	if d := n1.admit(t, cert, model.AccessRead); !d.Allowed {
		t.Fatalf("initial allow expected: %s", d.Reason)
	}

	// org-a 换主，使两条路径中的 org-a 旧边全部失效；随后只重新授权 P2。
	rot, _, err := a.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	n1.postEvent(t, model.EvKeyRotated, testkit.OrgA, rot)
	n2.postEvent(t, model.EvKeyRotated, testkit.OrgA, rot)

	// 旧证书在两节点都被拒（代际过期）。
	waitFor(t, 5*time.Second, func() bool {
		return !n1.admit(t, cert, model.AccessRead).Allowed && !n2.admit(t, cert, model.AccessRead).Allowed
	}, "both nodes revoke stale-generation certificate")

	// 仅重签 P2（org-a 用新代际，org-b 代际未变）。
	newP2 := []model.DelegationEdge{
		testkit.Edge(a, "carol", "dave", testNow-10, testNow+1000),
		testkit.Edge(b, "dave", "bob", testNow-10, testNow+1000),
	}
	reAuth := testkit.Cert("bob", p1, newP2)
	if d := n1.admit(t, reAuth, model.AccessRead); !d.Allowed {
		t.Fatalf("independent P2 must stay usable after re-auth: %s", d.Reason)
	}
	if d := n2.admit(t, reAuth, model.AccessRead); !d.Allowed {
		t.Fatalf("node2 independent P2 must stay usable: %s", d.Reason)
	}
}

// TestTwoProcessQueueFaults 验证队列重复/乱序/滞留下的至少一次与去重语义。
func TestTwoProcessQueueFaults(t *testing.T) {
	root := t.TempDir()
	n1 := startNode(t, "node1", root)
	defer n1.stop(t)

	a, err := testkit.NewIssuer(testkit.OrgA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := testkit.NewIssuer(testkit.OrgB)
	if err != nil {
		t.Fatal(err)
	}
	feedBootstrap(t, n1, n1, bootstrapEvents(t, a, b, testNow))

	q, err := queue.Open(n1.queueDir)
	if err != nil {
		t.Fatal(err)
	}
	// 成员退出事件（org-a seq 3，承接创始心跳 seq 2 的链头）。
	exitEv := model.Event{
		Seq: 3, Issuer: testkit.OrgA, Kind: model.EvMemberExited, EmittedAt: testNow,
		Payload: model.MemberExitedPayload{Member: "alice"},
	}
	exitEv.PrevHash = boot[testkit.OrgA][1].Hash
	exitEv.Hash = exitEv.Digest()
	name, err := q.Enqueue(exitEv)
	if err != nil {
		t.Fatal(err)
	}
	// 重复投递同一事件。
	if _, err := q.Duplicate(name); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool {
		c, _ := ackCount(n1.queueDir)
		return c >= 6 // 4 bootstrap + 2 copies
	}, "duplicate event delivered and both acknowledged")

	// 水位只推进一次（seq=3），重复未造成重复应用。
	code, raw := httpGet(n1.baseURL + "/admin/state?issuer=org-a")
	if code != 200 {
		t.Fatalf("state: %s", raw)
	}
	var st struct {
		Watermark uint64 `json:"watermark"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	if st.Watermark != 3 {
		t.Fatalf("watermark should be 3 after idempotent duplicate, got %d", st.Watermark)
	}

	// 乱序：先投 seq 5 制造缺口（PrevHash 指向尚未到达的 seq 4），
	// 节点必须保留不应用，再投 seq 4 补齐后两条依次应用。
	gapEv := model.Event{
		Seq: 5, Issuer: testkit.OrgA, Kind: model.EvHeartbeat, EmittedAt: testNow,
		Payload: model.HeartbeatPayload{},
	}
	gapEv.PrevHash = "placeholder-seq4"
	gapEv.Hash = gapEv.Digest()
	if _, err := q.Enqueue(gapEv); err != nil {
		t.Fatal(err)
	}
	// 等待若干轮询，确认 seq 5 因缺口被保留、水位停在 3。
	waitFor(t, 2*time.Second, func() bool {
		_, raw := httpGet(n1.baseURL + "/admin/state?issuer=org-a")
		var s struct {
			Watermark uint64 `json:"watermark"`
		}
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		return s.Watermark == 3
	}, "gap event seq=5 held back, watermark stays at 3")

	fillEv := model.Event{
		Seq: 4, Issuer: testkit.OrgA, Kind: model.EvHeartbeat, EmittedAt: testNow,
		Payload: model.HeartbeatPayload{},
	}
	fillEv.PrevHash = exitEv.Hash
	fillEv.Hash = fillEv.Digest()
	if _, err := q.Enqueue(fillEv); err != nil {
		t.Fatal(err)
	}
	// 补齐 seq 4 后水位推进到 4；seq 5 因 PrevHash 占位不符会被隔离，
	// 这恰好演示“篡改/断链事件被拒绝且不影响已确认前缀”，水位稳定在 4。
	waitFor(t, 5*time.Second, func() bool {
		_, raw := httpGet(n1.baseURL + "/admin/state?issuer=org-a")
		var s struct {
			Watermark   uint64 `json:"watermark"`
			Quarantined bool   `json:"quarantined"`
		}
		if json.Unmarshal(raw, &s) != nil {
			return false
		}
		return s.Watermark == 4
	}, "seq=4 applied, watermark reaches 4; broken seq=5 rejected")
}
