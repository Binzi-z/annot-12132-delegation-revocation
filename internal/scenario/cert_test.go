package scenario_test

import (
	"testing"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/model"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/scenario"
)

func TestCertificateVerifiesAllowed(t *testing.T) {
	f := scenario.NewFixture()
	req := localReq(scenario.Id(scenario.OrgB, scenario.Bob))
	d := f.State.Evaluate(req)
	if !d.Allowed {
		t.Fatalf("setup: expected allow\n%s", d.Explain())
	}
	cert := proto.FromDecision(f.State, d, req, scenario.OrgA, f.Reg)
	res := proto.Verify(f.Reg, cert)
	if !res.OK {
		t.Fatalf("certificate should verify: %v", res.Errors)
	}
	// A different registry must reject the signature.
	other := proto.Verify(auth.NewRegistry("a-different-seed"), cert)
	if other.OK {
		t.Fatalf("certificate must not verify under the wrong key registry")
	}
}

func TestCertificateTamperRejected(t *testing.T) {
	f := scenario.NewFixture()
	req := localReq(scenario.Id(scenario.OrgB, scenario.Bob))
	d := f.State.Evaluate(req)
	cert := proto.FromDecision(f.State, d, req, scenario.OrgA, f.Reg)
	cert.Allowed = false
	if res := proto.Verify(f.Reg, cert); res.OK {
		t.Fatalf("tampered verdict must fail verification")
	}
	// Tamper with an edge's scope.
	cert2 := proto.FromDecision(f.State, d, req, scenario.OrgA, f.Reg)
	cert2.Steps[0].Delegate.Scope = []string{"read", "write", "admin"}
	if res := proto.Verify(f.Reg, cert2); res.OK {
		t.Fatalf("tampered edge scope must fail verification")
	}
}

func TestCertificateRevokedChainVerifiesAsDeny(t *testing.T) {
	f := scenario.NewFixture()
	f.B.Revoke(scenario.OrgA, scenario.OrgA, 1, scenario.AdminA, scenario.EdgeADevBob)
	st, err := model.Fold(f.B.Events)
	if err != nil {
		t.Fatal(err)
	}
	req := localReq(scenario.Id(scenario.OrgB, scenario.Bob))
	d := st.Evaluate(req)
	if d.Allowed {
		t.Fatalf("expected deny")
	}
	cert := proto.FromDecision(st, d, req, scenario.OrgA, f.Reg)
	res := proto.Verify(f.Reg, cert)
	if !res.OK {
		t.Fatalf("deny certificate should verify: %v", res.Errors)
	}
	if res.Recomputed.Allowed {
		t.Fatalf("verifier must independently re-derive the deny")
	}
}
