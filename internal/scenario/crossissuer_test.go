package scenario_test

import (
	"testing"

	"ccrevoke/internal/model"
	"ccrevoke/internal/scenario"
)

// buildCrossIssuerWorld creates a chain that crosses orgs:
//
//	orgA alice(admin) --cross--> orgB:erin --sub--> orgB:bob
//
// The root is owned/issued by orgA; the second hop is issued by orgB. A LOCAL
// decision by orgA therefore depends on an orgB-issued edge, which matters under
// partition.
func buildCrossIssuerWorld(t *testing.T) *scenario.Fixture {
	t.Helper()
	reg := scenario.NewFixture().Reg
	b := scenario.NewBuilder(reg)
	o := scenario.OrgA

	b.Tenant(o, scenario.TenantA, scenario.OrgA)
	b.Resource(o, scenario.TenantA, scenario.ResA, scenario.OrgA)
	b.Authority(o, scenario.OrgA, 1, scenario.AdminA, true)
	// orgB declares erin as a delegator.
	b.Authority(scenario.OrgB, scenario.OrgB, 1, scenario.Erin, false)

	// root hop: orgA alice -> orgB:erin
	b.Delegate(o, scenario.OrgA, 1, scenario.AdminA, "cross-root", "", scenario.Id(scenario.OrgB, scenario.Erin), scenario.TenantA, scenario.ResA, 1, "read", "write")
	// orgB hop: erin -> bob
	b.Delegate(scenario.OrgB, scenario.OrgB, 1, scenario.Erin, "cross-leaf", "cross-root", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 1, "read")

	st, err := model.Fold(b.Events)
	if err != nil {
		t.Fatal(err)
	}
	return &scenario.Fixture{Reg: reg, B: b, State: st}
}

func TestCrossIssuerChainLocalUnderPartition(t *testing.T) {
	f := buildCrossIssuerWorld(t)
	bob := scenario.Id(scenario.OrgB, scenario.Bob)

	// Fully connected: LOCAL decision by orgA works.
	req := model.Request{Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: bob, Action: "read", Class: model.AccessLocal, NodeOrg: scenario.OrgA}
	if d := f.State.Evaluate(req); !d.Allowed {
		t.Fatalf("cross-issuer chain should authorize when connected:\n%s", d.Explain())
	}

	// orgB partitioned: LOCAL decisions still proceed from durable evidence
	// (the owner's authoritative view); the decision is not silently upgraded
	// from data orgA never received.
	req.Unreachable = []string{scenario.OrgB}
	if d := f.State.Evaluate(req); !d.Allowed {
		t.Fatalf("LOCAL decision should use durably-held orgB evidence under partition:\n%s", d.Explain())
	}
	// But a REMOTE_READ by orgB itself while orgB is (self-)partitioned from
	// orgA must be refused: the chain needs a fresh proof it cannot obtain.
	rr := model.Request{Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: bob, Action: "read", Class: model.AccessRemoteRead, NodeOrg: scenario.OrgB}
	rr.Unreachable = []string{scenario.OrgA}
	if d := f.State.Evaluate(rr); d.Allowed {
		t.Fatalf("REMOTE_READ with an unreachable chain issuer must deny:\n%s", d.Explain())
	}
}

func TestCrossIssuerRevocationByRemoteIssuer(t *testing.T) {
	f := buildCrossIssuerWorld(t)
	bob := scenario.Id(scenario.OrgB, scenario.Bob)
	// orgB revokes its own hop; orgA must deny bob once it durably receives it.
	f.B.Revoke(scenario.OrgB, scenario.OrgB, 1, scenario.Erin, "cross-leaf")
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	req := model.Request{Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: bob, Action: "read", Class: model.AccessLocal, NodeOrg: scenario.OrgA}
	if d := st.Evaluate(req); d.Allowed {
		t.Fatalf("remote-issuer revocation must deny the cross-issuer chain:\n%s", d.Explain())
	}
}