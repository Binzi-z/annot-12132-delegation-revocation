package node

import (
	"fmt"

	"ccrevoke/internal/event"
)

// SeedScenario idempotently seeds a named scenario on this node. It is used by
// the replay harness and by the interactive CLI. Seeding is a no-op if the node
// already has any events, so a restarted node does not double-mint.
func SeedScenario(n *Node, name string) error {
	if len(n.AllEvents()) > 0 {
		return nil
	}
	switch name {
	case "", "none":
		return nil
	case "world":
		// tenant-a/doc-a owned by orgA, two independent chains to orgB members.
		orgA, orgB := "orgA", "orgB"
		if n.cfg.Org == orgB {
			return nil // only orgA seeds the world; orgB receives it by replication
		}
		steps := []AuthorInput{
			{Kind: event.KindTenant, Issuer: orgA, Tenant: "tenant-a", OwnerOrg: orgA},
			{Kind: event.KindResource, Issuer: orgA, Tenant: "tenant-a", Resource: "doc-a", OwnerOrg: orgA},
			{Kind: event.KindAuthority, Issuer: orgA, Gen: 1, Actor: "alice", Admin: true},
			{Kind: event.KindAuthority, Issuer: orgA, Gen: 1, Actor: "dave"},
			{Kind: event.KindAuthority, Issuer: orgA, Gen: 1, Actor: "olga"},
			{Kind: event.KindDelegate, Issuer: orgA, Gen: 1, Actor: "alice", EdgeID: "e-a-admin-dev", Subject: "orgA:dave", Tenant: "tenant-a", Resource: "doc-a", Epoch: 1, Scope: []string{"read", "write"}},
			{Kind: event.KindDelegate, Issuer: orgA, Gen: 1, Actor: "dave", EdgeID: "e-a-dev-bob", Parent: "e-a-admin-dev", Subject: "orgB:bob", Tenant: "tenant-a", Resource: "doc-a", Epoch: 1, Scope: []string{"read"}},
			{Kind: event.KindDelegate, Issuer: orgA, Gen: 1, Actor: "alice", EdgeID: "e-a-admin-ops", Subject: "orgA:olga", Tenant: "tenant-a", Resource: "doc-a", Epoch: 1, Scope: []string{"read", "write"}},
			{Kind: event.KindDelegate, Issuer: orgA, Gen: 1, Actor: "olga", EdgeID: "e-a-ops-carl", Parent: "e-a-admin-ops", Subject: "orgB:carl", Tenant: "tenant-a", Resource: "doc-a", Epoch: 1, Scope: []string{"read"}},
		}
		for _, in := range steps {
			if _, err := n.Author(in); err != nil {
				return fmt.Errorf("seed %s step %s: %w", name, in.Kind, err)
			}
		}
		return nil
	default:
		return fmt.Errorf("unknown scenario %q", name)
	}
}
