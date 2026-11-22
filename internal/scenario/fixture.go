package scenario

import (
	"ccrevoke/internal/auth"
	"ccrevoke/internal/model"
)

// Standard world identifiers used across tests and scenarios.
const (
	OrgA = "orgA"
	OrgB = "orgB"

	TenantA = "tenant-a"
	ResA    = "doc-a"

	// Actors in orgA (resource owner / issuer).
	AdminA  = "alice"
	DevA    = "dave"
	OpsA    = "olga"
	RogueA  = "mallory"

	// Actors in orgB (cross-org delegate/client).
	Bob  = "bob"
	Carl = "carl"
	Erin = "erin"

	// Edge ids.
	EdgeAAdminDev = "e-a-admin-dev"
	EdgeADevBob   = "e-a-dev-bob"
	EdgeAAdminOps = "e-a-admin-ops"
	EdgeAOpsCarl  = "e-a-ops-carl"
	EdgeAOpsErin  = "e-a-ops-erin"
)

// Seed is the shared secret for the reference registry.
const Seed = "two-org-reference-seed"

// Fixture is a canonical scenario: tenant-a/doc-a owned by orgA, with two
// independent delegation chains reaching different orgB subjects:
//
//	chain 1: orgA alice(admin) -e-a-admin-dev-> orgA dave -e-a-dev-bob-> orgB bob
//	chain 2: orgA alice(admin) -e-a-admin-ops-> orgA olga -e-a-ops-carl-> orgB carl
//
// Both grant read on tenant-a/doc-a. They are independent: revoking one leaves
// the other usable.
type Fixture struct {
	Reg   *auth.Registry
	B     *Builder
	State *model.State
}

// NewFixture builds the canonical world.
func NewFixture() *Fixture {
	reg := auth.NewRegistry(Seed)
	b := NewBuilder(reg)
	o := OrgA

	b.Tenant(o, TenantA, OrgA)
	b.Resource(o, TenantA, ResA, OrgA)
	b.Authority(o, OrgA, 1, AdminA, true)
	b.Authority(o, OrgA, 1, DevA, false)
	b.Authority(o, OrgA, 1, OpsA, false)

	// Chain 1.
	b.Delegate(o, OrgA, 1, AdminA, EdgeAAdminDev, "", Id(OrgA, DevA), TenantA, ResA, 1, "read", "write")
	b.Delegate(o, OrgA, 1, DevA, EdgeADevBob, EdgeAAdminDev, Id(OrgB, Bob), TenantA, ResA, 1, "read")

	// Chain 2.
	b.Delegate(o, OrgA, 1, AdminA, EdgeAAdminOps, "", Id(OrgA, OpsA), TenantA, ResA, 1, "read", "write")
	b.Delegate(o, OrgA, 1, OpsA, EdgeAOpsCarl, EdgeAAdminOps, Id(OrgB, Carl), TenantA, ResA, 1, "read")

	st, err := model.Fold(b.Events)
	if err != nil {
		panic(err)
	}
	return &Fixture{Reg: reg, B: b, State: st}
}

// Id builds a canonical identity.
func Id(org, name string) string { return auth.Identity(org, name) }
