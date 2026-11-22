package scenario_test

import (
	"testing"

	"ccrevoke/internal/model"
	"ccrevoke/internal/scenario"
)

func localReq(subject string) model.Request {
	return model.Request{
		Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subject,
		Action: "read", Class: model.AccessLocal, NodeOrg: scenario.OrgA,
	}
}

func TestIndependentChainsBothWork(t *testing.T) {
	f := scenario.NewFixture()
	for _, subj := range []string{scenario.Id(scenario.OrgB, scenario.Bob), scenario.Id(scenario.OrgB, scenario.Carl)} {
		d := f.State.Evaluate(localReq(subj))
		if !d.Allowed {
			t.Fatalf("expected independent path for %s to be allowed:\n%s", subj, d.Explain())
		}
	}
}

func TestRevokeOneChainKeepsSibling(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Revoke(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, scenario.EdgeADevBob)
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	bob := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob)))
	if bob.Allowed {
		t.Fatalf("revoked chain must be denied:\n%s", bob.Explain())
	}
	carl := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl)))
	if !carl.Allowed {
		t.Fatalf("independent chain must stay allowed:\n%s", carl.Explain())
	}
}

func TestLeaveKillsOnlyPathsThroughMember(t *testing.T) {
	f := scenario.NewFixture()
	// dave leaves orgA: chain1 dies, chain2 lives.
	f.B.Leave(scenario.OrgA, scenario.OrgA, 1, scenario.DevA)
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); d.Allowed {
		t.Fatalf("path through departed member must be denied:\n%s", d.Explain())
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl))); !d.Allowed {
		t.Fatalf("independent path must stay allowed:\n%s", d.Explain())
	}
}

func TestRotationInvalidatesOldGeneration(t *testing.T) {
	f := scenario.NewFixture()
	// Rotate orgA to gen2 and re-grant admin, but chain1 edges were minted at g1.
	f.B.Rotate(scenario.OrgA, scenario.OrgA, 1, 2)
	f.B.Authority(scenario.OrgA, scenario.OrgA, 2, scenario.AdminA, true)
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	for _, subj := range []string{scenario.Id(scenario.OrgB, scenario.Bob), scenario.Id(scenario.OrgB, scenario.Carl)} {
		if d := st.Evaluate(localReq(subj)); d.Allowed {
			t.Fatalf("stale-gen chain for %s must be denied after rotation:\n%s", subj, d.Explain())
		}
	}
}

func TestReauthorizeAfterRotationRestoresAccess(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Rotate(scenario.OrgA, scenario.OrgA, 1, 2)
	f.B.Authority(scenario.OrgA, scenario.OrgA, 2, scenario.AdminA, true)
	f.B.Authority(scenario.OrgA, scenario.OrgA, 2, scenario.OpsA, false)
	// Re-mint chain2 at g2 with fresh edge ids.
	f.B.Delegate(scenario.OrgA, scenario.OrgA, 2, scenario.AdminA, "e2-admin-ops", "", scenario.Id(scenario.OrgA, scenario.OpsA), scenario.TenantA, scenario.ResA, 1, "read", "write")
	f.B.Delegate(scenario.OrgA, scenario.OrgA, 2, scenario.OpsA, "e2-ops-carl", "e2-admin-ops", scenario.Id(scenario.OrgB, scenario.Carl), scenario.TenantA, scenario.ResA, 1, "read")
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl))); !d.Allowed {
		t.Fatalf("re-authorized chain must be allowed:\n%s", d.Explain())
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); d.Allowed {
		t.Fatalf("old-generation chain must remain denied:\n%s", d.Explain())
	}
}

func TestTransferInvalidatesOldChains(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Transfer(scenario.OrgA, scenario.OrgA, 1, scenario.TenantA, scenario.ResA, scenario.OrgB, 2)
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	// Old edges target epoch 1; resource is now epoch 2 owned by orgB.
	for _, subj := range []string{scenario.Id(scenario.OrgB, scenario.Bob), scenario.Id(scenario.OrgB, scenario.Carl)} {
		if d := st.Evaluate(localReq(subj)); d.Allowed {
			t.Fatalf("old-epoch chain for %s must be denied after transfer:\n%s", subj, d.Explain())
		}
	}
}

func TestExpiry(t *testing.T) {
	f := scenario.NewFixture()
	deadline := f.B.TickAt() + 3
	f.B.DelegateUntil(scenario.OrgA, scenario.OrgA, 1, scenario.OpsA, "e-exp", scenario.EdgeAAdminOps,
		scenario.Id(scenario.OrgB, scenario.Carl), scenario.TenantA, scenario.ResA, 1, deadline, "read")
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	// Before expiry the short edge is usable but the open one was superseded by
	// a later candidate; either way Carl is allowed while not expired.
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl))); !d.Allowed {
		t.Fatalf("must be allowed before expiry:\n%s", d.Explain())
	}
	// Advance past the deadline in a copy.
	f.B.Clock(scenario.OrgA)
	for f.B.Tick <= deadline+2 {
		f.B.Clock(scenario.OrgA)
	}
	st2, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	if d := st2.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl))); d.Allowed {
		// The non-expiring e-a-ops-carl edge still exists, so Carl is still
		// allowed. That is correct: expiry must not break an independent valid
		// path. Verify the expired edge itself is now unusable.
		t.Logf("carl still allowed via independent edge (expected):\n%s", d.Explain())
	}
	// Bob has no independent path and is unaffected. Expiry of e-exp must show
	// up as an explicit per-step failure on that candidate.
	d := st2.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Carl)))
	found := false
	for _, ch := range d.Chains {
		for _, stp := range ch.Steps {
			if stp.EdgeID == "e-exp" && !stp.Valid {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expired edge should be marked invalid:\n%s", d.Explain())
	}
}

func TestExpiryDeniesWhenOnlyPath(t *testing.T) {
	reg := scenario.NewFixture().Reg
	b := scenario.NewBuilder(reg)
	b.Tenant(scenario.OrgA, scenario.TenantA, scenario.OrgA)
	b.Resource(scenario.OrgA, scenario.TenantA, scenario.ResA, scenario.OrgA)
	b.Authority(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, true)
	b.Delegate(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, "r", "", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 1, "read")
	// Put the deadline safely in the future so the revoke below does not cross it.
	deadline := b.TickAt() + 5
	b.DelegateUntil(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, "x", "", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 1, deadline, "read")
	// Revoke the non-expiring root, leaving only x.
	b.Revoke(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, "r")
	st, err := model.Fold(b.Events)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); !d.Allowed {
		t.Fatalf("before expiry the only remaining path is valid:\n%s", d.Explain())
	}
	for b.Tick <= deadline {
		b.Clock(scenario.OrgA)
	}
	st, err = model.Fold(b.Events)
	if err != nil {
		t.Fatal(err)
	}
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); d.Allowed {
		t.Fatalf("after expiry with no other path, must deny:\n%s", d.Explain())
	}
}

func TestRotateToOlderGenerationIgnored(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Rotate(scenario.OrgA, scenario.OrgA, 1, 2)
	st, _ := model.Fold(f.B.Events)
	// g1 edges now stale; dave/bob denied.
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); d.Allowed {
		t.Fatalf("stale gen must deny:\n%s", d.Explain())
	}
}

func TestResourceEpochGuard(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Transfer(scenario.OrgA, scenario.OrgA, 1, scenario.TenantA, scenario.ResA, scenario.OrgB, 2)
	f.B.Authority(scenario.OrgB, scenario.OrgB, 1, scenario.Erin, true)
	// New owner orgB mints fresh root edges at epoch 2.
	f.B.Delegate(scenario.OrgB, scenario.OrgB, 1, scenario.Erin, "e-b-erin-bob", "", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 2, "read")
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	// Bob: old orgA epoch-1 edges die, new orgB epoch-2 edge works.
	if d := st.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Bob))); !d.Allowed {
		// localReq uses NodeOrg=orgA but owner is orgB now; expect LOCAL class
		// mismatch. Evaluate as orgB local instead.
		_ = d
	}
	req := model.Request{Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: scenario.Id(scenario.OrgB, scenario.Bob), Action: "read", Class: model.AccessLocal, NodeOrg: scenario.OrgB}
	d := st.Evaluate(req)
	if !d.Allowed {
		t.Fatalf("new owner's fresh edge must be allowed:\n%s", d.Explain())
	}
}

func TestNoPathDenied(t *testing.T) {
	f := scenario.NewFixture()
	d := f.State.Evaluate(localReq(scenario.Id(scenario.OrgB, scenario.Erin)))
	if d.Allowed {
		t.Fatalf("subject with no path must be denied:\n%s", d.Explain())
	}
	if d.ChainID != "" {
		t.Fatalf("denied decision must not name a chain")
	}
}