package interleave_test

import (
	"testing"

	"ccrevoke/internal/interleave"
)

// TestRotationEvidenceIsContiguous is the regression test for the bug the
// enumerator originally found: collapsing per-issuer rotation evidence to a
// single record made a mid-chain rotation replay look like a fresh generation
// gap, which quarantined the issuer and broke certificate re-derivation. Each
// rotation step must be retained and produce a verifiable certificate after a
// compaction + restart.
func TestRotationEvidenceIsContiguous(t *testing.T) {
	m := interleave.New()
	var compactAct, rotAct, restartAct interleave.Action
	for _, a := range interleave.Actions(m) {
		switch a.Label {
		case "compact (snapshot + retain evidence)":
			compactAct = a
		case "rotate orgA to next generation (invalidates prior-gen edges)":
			rotAct = a
		case "restart (recover from snapshot + evidence)":
			restartAct = a
		}
	}
	compactAct.Apply(m)
	rotAct.Apply(m)
	rotAct.Apply(m)
	restartAct.Apply(m)

	if err := m.VerifyCert(interleave.BobID(), "read"); err != nil {
		t.Fatalf("certificate after double rotation + compaction + restart: %v", err)
	}
	if err := m.VerifyCert(interleave.CarlID(), "read"); err != nil {
		t.Fatalf("certificate for carl: %v", err)
	}
}
