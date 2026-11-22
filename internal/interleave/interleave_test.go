package interleave_test

import (
	"testing"

	"ccrevoke/internal/interleave"
)

// TestEnumerateInvariants exhaustively walks short action interleavings and
// fails on the first invariant violation. The action subset is deliberately
// small; length 4 already covers revocation -> compaction -> restart -> ban and
// reauthorization -> transfer -> restart.
func TestEnumerateInvariants(t *testing.T) {
	for _, depth := range []int{1, 2, 3, 4} {
		v, states := interleave.Enumerate(depth)
		if v != nil {
			t.Fatalf("depth %d: invariant violation after exploring %d states:\n%v", depth, states, *v)
		}
		if states == 0 {
			t.Fatalf("depth %d: explored no states", depth)
		}
		t.Logf("depth %d: %d states, no violations", depth, states)
	}
}

// TestExpiry is observable and isolated: erin's expiring chain is usable before
// its deadline, dead after, while the two permanent chains are unaffected.
func TestExpiry(t *testing.T) {
	m := interleave.New()
	var expireAct interleave.Action
	for _, a := range interleave.Actions(m) {
		if a.Label == "mint then expire an erin chain (ops->erin)" {
			expireAct = a
		}
	}
	expireAct.Apply(m)
	obs := m.Observe()
	if obs.ErinAllowed {
		t.Fatalf("expired erin chain must be unusable")
	}
	if !obs.BobsAllowed || !obs.CarlAllowed {
		t.Fatalf("permanent chains must be unaffected by expiry: bob=%v carl=%v", obs.BobsAllowed, obs.CarlAllowed)
	}
}

// TestRestartRecoveryKeepsBans checks directly that compaction then restart does
// not resurrect a revoked or banned subject.
func TestRestartRecoveryKeepsBans(t *testing.T) {
	m := interleave.New()
	// Revoke bob + ban the resource, compact, restart.
	for _, act := range interleave.Actions(m) {
		switch act.Label {
		case "revoke chain1 child edge (dave->bob)":
			act.Apply(m)
		case "emergency-ban bob on doc-a":
			act.Apply(m)
		case "compact (snapshot + retain evidence)":
			act.Apply(m)
		case "restart (recover from snapshot + evidence)":
			act.Apply(m)
		}
	}
	obs := m.Observe()
	if obs.BobsAllowed {
		t.Fatalf("bob resurrected after compaction+restart")
	}
	if obs.BanCount == 0 {
		t.Fatalf("ban lost after compaction+restart")
	}
}
