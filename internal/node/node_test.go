package node_test

import (
	"testing"

	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/node"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/scenario"
)

func openNode(t *testing.T, org string, dir string) *node.Node {
	t.Helper()
	n, err := node.Open(node.Config{Org: org, Dir: dir, Seed: scenario.Seed, TickStep: 1})
	if err != nil {
		t.Fatalf("open %s: %v", org, err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// bootstrap builds the canonical world on nodeA and replicates everything to
// nodeB. Returns both nodes.
func bootstrap(t *testing.T) (*node.Node, *node.Node) {
	t.Helper()
	a := openNode(t, scenario.OrgA, t.TempDir())
	b := openNode(t, scenario.OrgB, t.TempDir())
	buildWorld(t, a)
	replicate(t, a, b)
	return a, b
}

func buildWorld(t *testing.T, a *node.Node) {
	t.Helper()
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindTenant, Tenant: scenario.TenantA, OwnerOrg: scenario.OrgA})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindResource, Tenant: scenario.TenantA, Resource: scenario.ResA, OwnerOrg: scenario.OrgA})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindAuthority, Gen: 1, Actor: scenario.AdminA, Admin: true})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindAuthority, Gen: 1, Actor: scenario.DevA})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindAuthority, Gen: 1, Actor: scenario.OpsA})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindDelegate, Gen: 1, Actor: scenario.AdminA, EdgeID: scenario.EdgeAAdminDev, Subject: scenario.Id(scenario.OrgA, scenario.DevA), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read", "write"}})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindDelegate, Gen: 1, Actor: scenario.DevA, EdgeID: scenario.EdgeADevBob, Parent: scenario.EdgeAAdminDev, Subject: scenario.Id(scenario.OrgB, scenario.Bob), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read"}})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindDelegate, Gen: 1, Actor: scenario.AdminA, EdgeID: scenario.EdgeAAdminOps, Subject: scenario.Id(scenario.OrgA, scenario.OpsA), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read", "write"}})
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindDelegate, Gen: 1, Actor: scenario.OpsA, EdgeID: scenario.EdgeAOpsCarl, Parent: scenario.EdgeAAdminOps, Subject: scenario.Id(scenario.OrgB, scenario.Carl), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read"}})
}

func mustAuthor(t *testing.T, n *node.Node, in node.AuthorInput) event.Event {
	t.Helper()
	ev, err := n.Author(in)
	if err != nil {
		t.Fatalf("author %s: %v", in.Kind, err)
	}
	return ev
}

// replicate delivers all of src's events to dst, in canonical order.
func replicate(t *testing.T, src, dst *node.Node) {
	t.Helper()
	evs := src.AllEvents()
	event.CanonicalOrder(evs)
	for _, e := range evs {
		if e.Node == dst.Org() {
			continue
		}
		if err := dst.Ingest(e); err != nil {
			t.Fatalf("ingest %s: %v", e.String(), err)
		}
	}
}

func req(subject string, class model.AccessClass, nodeOrg string) model.Request {
	return model.Request{Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subject, Action: "read", Class: class, NodeOrg: nodeOrg}
}

func TestIndependentPathsAcrossNodes(t *testing.T) {
	a, b := bootstrap(t)
	// Node B evaluates a REMOTE_READ of orgA's resource for its own members.
	d, cert := b.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Bob), model.AccessRemoteRead, scenario.OrgB))
	if !d.Allowed {
		t.Fatalf("bob remote read should be allowed:\n%s", d.Explain())
	}
	if res := proto.Verify(a.Registry(), cert); !res.OK {
		t.Fatalf("certificate from B must verify against the shared registry: %v", res.Errors)
	}
	// Carl independent path also works.
	d2, _ := b.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Carl), model.AccessRemoteRead, scenario.OrgB))
	if !d2.Allowed {
		t.Fatalf("carl remote read should be allowed:\n%s", d2.Explain())
	}
}

func TestRevocationPropagation(t *testing.T) {
	a, b := bootstrap(t)
	// Revoke bob's chain on A, replicate, then both nodes must deny bob but
	// keep carl working.
	mustAuthor(t, a, node.AuthorInput{Kind: event.KindRevoke, Gen: 1, Actor: scenario.AdminA, EdgeID: scenario.EdgeADevBob, EvidenceID: "rev-bob"})
	replicate(t, a, b)
	for name, n := range map[string]*node.Node{"A": a, "B": b} {
		if d, _ := n.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Bob), model.AccessLocal, scenario.OrgA)); d.Allowed {
			t.Fatalf("node %s should deny bob after revocation:\n%s", name, d.Explain())
		}
		if d, _ := n.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Carl), model.AccessLocal, scenario.OrgA)); !d.Allowed {
			t.Fatalf("node %s should keep carl allowed:\n%s", name, d.Explain())
		}
	}
}

func TestPartitionSemantics(t *testing.T) {
	a, b := bootstrap(t)
	// Partition: B cannot reach A.
	bob := scenario.Id(scenario.OrgB, scenario.Bob)

	// REMOTE_READ of orgA's resource while orgA unreachable: denied (no fresh
	// cross-boundary proof), even though B has the data locally.
	r := req(bob, model.AccessRemoteRead, scenario.OrgB)
	r.Unreachable = []string{scenario.OrgA}
	if d, _ := b.Evaluate(r); d.Allowed {
		t.Fatalf("remote read while owner partitioned must deny:\n%s", d.Explain())
	}
	// REMOTE_WRITE while owner partitioned: fail closed.
	w := req(bob, model.AccessRemoteWrite, scenario.OrgB)
	w.Action = "write"
	w.Unreachable = []string{scenario.OrgA}
	if d, _ := b.Evaluate(w); d.Allowed {
		t.Fatalf("remote write while owner partitioned must deny:\n%s", d.Explain())
	}
	// LOCAL access decided by A itself is unaffected: A is never partitioned
	// from itself.
	if d, _ := a.Evaluate(req(bob, model.AccessLocal, scenario.OrgA)); !d.Allowed {
		t.Fatalf("owner-local access must remain allowed while the peer is down:\n%s", d.Explain())
	}
}

func TestEmergencyBanSurvivesCompactionAndRestart(t *testing.T) {
	dirA := t.TempDir()
	a := openNode(t, scenario.OrgA, dirA)
	buildWorld(t, a)
	// Ban bob's entire resource access from orgA (emergency).
	ban := mustAuthor(t, a, node.AuthorInput{Kind: event.KindBan, Gen: 1, Actor: scenario.AdminA, Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: scenario.Id(scenario.OrgB, scenario.Bob), Reason: "compromise"})
	if d, _ := a.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Bob), model.AccessLocal, scenario.OrgA)); d.Allowed {
		t.Fatalf("banned subject must be denied")
	}
	if err := a.Checkpoint(); err != nil {
		t.Fatal(err)
	}
	a.Close()

	// Restart.
	a2 := openNode(t, scenario.OrgA, dirA)
	if d, _ := a2.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Bob), model.AccessLocal, scenario.OrgA)); d.Allowed {
		t.Fatalf("ban lost across compaction+restart:\n%s", d.Explain())
	}
	found := false
	for _, r := range a2.Evidence() {
		if r.EvidenceID == ban.EvidenceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ban evidence not retained")
	}
	// Independent path (carl) still works.
	if d, _ := a2.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Carl), model.AccessLocal, scenario.OrgA)); !d.Allowed {
		t.Fatalf("independent path broken by ban on bob:\n%s", d.Explain())
	}
}

func TestBanPropagationAndDurableOnPeer(t *testing.T) {
	a, b := bootstrap(t)
	// Ban originates on B (orgB's emergency disable) for bob.
	ban := mustAuthor(t, b, node.AuthorInput{Kind: event.KindBan, Gen: 1, Actor: scenario.Bob, Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: scenario.Id(scenario.OrgB, scenario.Bob), Reason: "orgB recall"})
	// Sync evidence to A out-of-band (peer evidence merge), which is how a ban
	// stays durable even if the full event stream is delayed.
	if err := a.MergePeerEvidence([]event.EvidenceRecord{event.FromEvent(ban)}); err != nil {
		t.Fatal(err)
	}
	// A must now deny bob.
	if d, _ := a.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Bob), model.AccessLocal, scenario.OrgA)); d.Allowed {
		t.Fatalf("ban from peer must deny on A:\n%s", d.Explain())
	}
	// Carl independent path still fine.
	if d, _ := a.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Carl), model.AccessLocal, scenario.OrgA)); !d.Allowed {
		t.Fatalf("ban on bob must not affect carl:\n%s", d.Explain())
	}
}

func TestIssuerFaultIsolation(t *testing.T) {
	a := openNode(t, scenario.OrgA, t.TempDir())
	buildWorld(t, a)
	b := openNode(t, scenario.OrgB, t.TempDir())
	// orgB declares an authority at g1, then issues a rotation that skips to
	// g6. The skip is a per-issuer fault.
	if ev, err := b.Author(node.AuthorInput{Kind: event.KindAuthority, Gen: 1, Actor: scenario.Bob, Admin: true}); err == nil {
		replicate(t, b, a)
		_ = ev
	} else {
		t.Fatalf("authority: %v", err)
	}
	rot, err := b.Author(node.AuthorInput{Kind: event.KindRotate, Issuer: scenario.OrgB, FromGen: 5, ToGen: 6, EvidenceID: "rot-bad"})
	if err != nil {
		t.Fatalf("author rotate: %v", err)
	}
	if err := a.Ingest(rot); err != nil {
		t.Fatalf("ingest rotate: %v", err)
	}
	// orgB is now quarantined on A; orgA decisions still work.
	if d, _ := a.Evaluate(req(scenario.Id(scenario.OrgB, scenario.Carl), model.AccessLocal, scenario.OrgA)); !d.Allowed {
		t.Fatalf("orgA local decision must be unaffected by orgB fault:\n%s", d.Explain())
	}
	sum := a.Quarantined()
	if _, ok := sum[scenario.OrgB]; !ok {
		t.Fatalf("expected orgB quarantined, got %v", sum)
	}
	if _, ok := sum[scenario.OrgA]; ok {
		t.Fatalf("orgA must not be quarantined")
	}
}
