package replay_test

import (
	"testing"

	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/node"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/replay"
	"ccrevoke/internal/scenario"
)

// TestMinimalCounterexampleControllableQueue is the explicitly queue-driven
// replay of the smallest counterexample the task asks for:
//
//  1. Two processes share the canonical world (two independent chains).
//  2. A revoke of chain1 is staged but *held* (partition).
//  3. B keeps admitting bob on stale local data (this is the bug to avoid).
//  4. The held revoke is released and delivered; B must deny bob.
//  5. An old, signed duplicate of bob's pre-revoke delegation arrives late and
//     is delivered twice; it must not restore bob.
//  6. Carl's independent chain must remain admitted throughout.
//
// Every step prints the admission certificate so the verdict is checkable.
func TestMinimalCounterexampleControllableQueue(t *testing.T) {
	w, err := replay.StartWorld(seed, 1)
	if err != nil {
		t.Fatalf("start world: %v", err)
	}
	t.Cleanup(func() { w.Close(false) })
	if err := w.Sync(0); err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	bob := scenario.Id(scenario.OrgB, scenario.Bob)
	carl := scenario.Id(scenario.OrgB, scenario.Carl)

	// Step 2: stage the revoke but hold it (partition A->B).
	if _, err := w.A.Client().Author(node.AuthorInput{
		Kind: event.KindRevoke, Issuer: scenario.OrgA, Gen: 1, Actor: scenario.AdminA,
		EdgeID: scenario.EdgeADevBob, EvidenceID: "rev-min",
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Pull(scenario.OrgA, scenario.OrgB); err != nil {
		t.Fatal(err)
	}
	w.Queue.Hold(w.Queue.Len())
	if w.Queue.Len() == 0 {
		t.Fatalf("expected staged messages for B")
	}

	// Step 3: while partitioned, B still admits bob from its durable state and
	// carl independently. This is expected: B has not yet received the revoke.
	bobBefore, certBefore, err := w.B.Client().Evaluate(remoteRead(bob))
	if err != nil {
		t.Fatal(err)
	}
	if !bobBefore.Allowed {
		t.Fatalf("before the revoke arrives, B should admit bob from durable state:\n%s", bobBefore.Explain())
	}
	if res := proto.Verify(scenario.NewFixture().Reg, certBefore); !res.OK {
		t.Fatalf("pre-revoke certificate must verify: %v", res.Errors)
	}
	carlBefore, _, _ := w.B.Client().Evaluate(remoteRead(carl))
	if !carlBefore.Allowed {
		t.Fatalf("carl must be admitted throughout")
	}

	// Step 4: release and deliver the held revoke.
	w.Queue.Release()
	if err := w.Deliver(0); err != nil {
		t.Fatalf("deliver revoke: %v", err)
	}
	bobAfter, certAfter, err := w.B.Client().Evaluate(remoteRead(bob))
	if err != nil {
		t.Fatal(err)
	}
	if bobAfter.Allowed {
		t.Fatalf("bob must be denied after the held revoke is delivered:\n%s", bobAfter.Explain())
	}
	if res := proto.Verify(scenario.NewFixture().Reg, certAfter); !res.OK {
		t.Fatalf("post-revoke (deny) certificate must verify: %v", res.Errors)
	}
	if certAfter.Reasons == nil {
		t.Fatalf("deny certificate should explain its basis")
	}

	// Step 5: replay the old, still-validly-signed delegation for bob's chain,
	// twice. Stale signed data must not resurrect the chain.
	stale := staleDelegation(t, w, scenario.EdgeADevBob)
	for i := 0; i < 2; i++ {
		if err := w.B.Client().Ingest(stale); err != nil {
			t.Fatalf("stale replay %d: %v", i, err)
		}
	}
	if d, _, _ := w.B.Client().Evaluate(remoteRead(bob)); d.Allowed {
		t.Fatalf("stale replay resurrected a revoked chain:\n%s", d.Explain())
	}

	// Step 6: carl still fine.
	if d, _, _ := w.B.Client().Evaluate(remoteRead(carl)); !d.Allowed {
		t.Fatalf("carl denied despite independent chain:\n%s", d.Explain())
	}
}

// TestDropThenRetryEventuallyConverges drops the first replication batch, then
// syncs again: the revoke must still take effect exactly once.
func TestDropThenRetryEventuallyConverges(t *testing.T) {
	w, err := replay.StartWorld(seed, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close(false) })
	if err := w.Sync(0); err != nil {
		t.Fatal(err)
	}
	if _, err := w.A.Client().Author(node.AuthorInput{
		Kind: event.KindRevoke, Issuer: scenario.OrgA, Gen: 1, Actor: scenario.AdminA,
		EdgeID: scenario.EdgeADevBob, EvidenceID: "rev-drop",
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.PullBoth(); err != nil {
		t.Fatal(err)
	}
	// Drop everything; nothing delivered.
	w.Queue.DropNext(w.Queue.Len())
	if err := w.Deliver(0); err != nil {
		t.Fatal(err)
	}
	bob := scenario.Id(scenario.OrgB, scenario.Bob)
	if d, _, _ := w.B.Client().Evaluate(remoteRead(bob)); !d.Allowed {
		t.Fatalf("before retry B has not seen the revoke and should still admit bob")
	}
	// Retry: state-based pull finds the still-missing event and delivers it.
	if err := w.Sync(0); err != nil {
		t.Fatal(err)
	}
	if d, _, _ := w.B.Client().Evaluate(remoteRead(bob)); d.Allowed {
		t.Fatalf("revoke did not converge after retry:\n%s", d.Explain())
	}
}

// TestWatermarkMigrationAcrossRestart verifies per-issuer watermarks are
// durable and monotonically non-regressing across restart.
func TestWatermarkMigrationAcrossRestart(t *testing.T) {
	w, err := replay.StartWorld(seed, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close(false) })
	if err := w.Sync(0); err != nil {
		t.Fatal(err)
	}
	before, err := w.B.Client().Summary()
	if err != nil {
		t.Fatal(err)
	}
	beforeWM := watermarkTick(before, scenario.OrgA)
	if beforeWM == 0 {
		t.Fatalf("expected a watermark for orgA")
	}
	if err := w.B.Client().Checkpoint(); err != nil {
		t.Fatal(err)
	}
	if err := w.B.Restart(seed, 1); err != nil {
		t.Fatal(err)
	}
	after, err := w.B.Client().Summary()
	if err != nil {
		t.Fatal(err)
	}
	afterWM := watermarkTick(after, scenario.OrgA)
	if afterWM < beforeWM {
		t.Fatalf("watermark regressed across restart: %d -> %d", beforeWM, afterWM)
	}
}

// staleDelegation finds the signed delegation event for an edge that A holds.
func staleDelegation(t *testing.T, w *replay.World, edgeID string) event.Event {
	t.Helper()
	evs, err := w.A.Client().Events(scenario.OrgA, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Kind == event.KindDelegate && e.EdgeID == edgeID {
			return e
		}
	}
	t.Fatalf("delegation for %s not found", edgeID)
	return event.Event{}
}

func watermarkTick(summary map[string]any, org string) int64 {
	wm, ok := summary["watermarks"].(map[string]any)
	if !ok {
		return 0
	}
	entry, ok := wm[org].(map[string]any)
	if !ok {
		return 0
	}
	switch v := entry["tick"].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	}
	return 0
}

var _ = model.AccessLocal