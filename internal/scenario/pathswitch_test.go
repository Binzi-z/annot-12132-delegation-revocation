package scenario_test

import (
	"testing"

	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/scenario"
)

// TestPathSwitchKeepsBannedPathEvidence models: a subject has two paths; a ban
// applies only to the longer path's intermediate edge; the shorter path is
// chosen. The decision is ALLOW via the short path, but the ban evidence for the
// longer path must remain in the certificate's evidence set and in state.
func TestPathSwitchKeepsBannedPathEvidence(t *testing.T) {
	reg := scenario.NewFixture().Reg
	b := scenario.NewBuilder(reg)
	o := scenario.OrgA

	b.Tenant(o, scenario.TenantA, scenario.OrgA)
	b.Resource(o, scenario.TenantA, scenario.ResA, scenario.OrgA)
	b.Authority(o, scenario.OrgA, 1, scenario.AdminA, true)
	b.Authority(o, scenario.OrgA, 1, scenario.DevA, false)

	// Short path: admin -> bob directly.
	b.Delegate(o, scenario.OrgA, 1, scenario.AdminA, "short", "", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 1, "read", "write")
	// Long path: admin -> dave -> bob.
	b.Delegate(o, scenario.OrgA, 1, scenario.AdminA, "long-root", "", scenario.Id(scenario.OrgA, scenario.DevA), scenario.TenantA, scenario.ResA, 1, "read", "write")
	b.Delegate(o, scenario.OrgA, 1, scenario.DevA, "long-leaf", "long-root", scenario.Id(scenario.OrgB, scenario.Bob), scenario.TenantA, scenario.ResA, 1, "read")
	// Emergency ban targeted at the long path's leaf edge.
	ban := b.Ban(o, scenario.OrgA, 1, scenario.TenantA, scenario.ResA, "", "long-leaf", "targeted")

	st, err := model.Fold(b.Events)
	if err != nil {
		t.Fatal(err)
	}
	req := model.Request{
		Tenant: scenario.TenantA, Resource: scenario.ResA,
		Subject: scenario.Id(scenario.OrgB, scenario.Bob), Action: "read",
		Class: model.AccessLocal, NodeOrg: scenario.OrgA,
	}
	d := st.Evaluate(req)
	if !d.Allowed {
		t.Fatalf("short independent path should be allowed:\n%s", d.Explain())
	}
	if d.ChainID != "short" {
		t.Fatalf("expected the shortest path to be chosen, got %q", d.ChainID)
	}
	// The ban on the long path must still be present in state and evidence.
	if len(st.Bans) != 1 {
		t.Fatalf("ban evidence lost on path switch: %d bans", len(st.Bans))
	}
	found := false
	for _, r := range st.Evidence {
		if r.EvidenceID == ban.EvidenceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ban evidence not retained in state after path switch")
	}
	// Deny the short path too; now only the banned long path remains, and the
	// certificate's deny must cite the ban.
	b.Revoke(o, scenario.OrgA, 1, scenario.AdminA, "short")
	st, err = model.Fold(b.Events)
	if err != nil {
		t.Fatal(err)
	}
	d = st.Evaluate(req)
	if d.Allowed {
		t.Fatalf("with short path revoked, banned long path must deny:\n%s", d.Explain())
	}
	cert := proto.FromDecision(st, d, req, scenario.OrgA, reg)
	if res := proto.Verify(reg, cert); !res.OK {
		t.Fatalf("deny certificate must verify: %v", res.Errors)
	}
	hasBan := false
	for _, r := range cert.Evidence {
		if r.Kind == event.KindBan && r.EvidenceID == ban.EvidenceID {
			hasBan = true
		}
	}
	if !hasBan {
		t.Fatalf("deny certificate does not cite the ban evidence")
	}
}