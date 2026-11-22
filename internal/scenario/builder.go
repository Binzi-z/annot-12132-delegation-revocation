// Package scenario provides deterministic builders for signed canonical events
// and a two-node world with a controllable delivery queue. It is shared by the
// model tests, the interleaving enumerator, and the two-process replay.
package scenario

import (
	"fmt"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
)

// Builder authors hash-chained events per origin into an in-memory list. It
// signs with the shared registry so the resulting events are independently
// verifiable, exactly like events a node would append.
type Builder struct {
	Reg     *auth.Registry
	Tick    int64
	step    int64
	seq     map[string]uint64
	prev    map[string]string
	Events  []event.Event
	evidSeq int
}

// NewBuilder returns a builder over the shared registry.
func NewBuilder(reg *auth.Registry) *Builder {
	return &Builder{Reg: reg, step: 1, seq: map[string]uint64{}, prev: map[string]string{}}
}

// SetStep sets the logical time increment per event.
func (b *Builder) SetStep(s int64) *Builder {
	if s > 0 {
		b.step = s
	}
	return b
}

// NewEvidenceID returns a deterministic evidence id.
func (b *Builder) NewEvidenceID(prefix string) string {
	b.evidSeq++
	return fmt.Sprintf("%s-%04d", prefix, b.evidSeq)
}

// Author builds, signs, and appends one event.
func (b *Builder) Author(origin string, in event.Event) event.Event {
	b.Tick += b.step
	e := in
	e.Node = origin
	e.Tick = b.Tick
	b.seq[origin]++
	e.Seq = b.seq[origin]
	e.Prev = b.prev[origin]
	e.Sign(b.Reg)
	b.prev[origin] = e.Hash
	b.Events = append(b.Events, e)
	return e
}

// TickAt returns the tick an author call would use.
func (b *Builder) TickAt() int64 { return b.Tick + b.step }

// Tenant registers a tenant owned by org.
func (b *Builder) Tenant(origin, tenant, org string) event.Event {
	return b.Author(origin, event.Event{Kind: event.KindTenant, Issuer: org, Tenant: tenant, OwnerOrg: org})
}

// Resource registers a resource owned by org.
func (b *Builder) Resource(origin, tenant, resource, org string) event.Event {
	return b.Author(origin, event.Event{Kind: event.KindResource, Issuer: org, Tenant: tenant, Resource: resource, OwnerOrg: org})
}

// Authority declares that member may delegate at gen for org.
func (b *Builder) Authority(origin, org string, gen int, member string, admin bool) event.Event {
	return b.Author(origin, event.Event{Kind: event.KindAuthority, Issuer: org, Gen: gen, Actor: member, Admin: admin})
}

// Rotate supersedes fromGen with toGen for org.
func (b *Builder) Rotate(origin, org string, fromGen, toGen int) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindRotate, Issuer: org, Gen: toGen, FromGen: fromGen, ToGen: toGen,
		EvidenceID: b.NewEvidenceID("rot"),
	})
}

// Delegate mints one edge. scopes grant actions on tenant/resource.
func (b *Builder) Delegate(origin, org string, gen int, actor, edge, parent, subject, tenant, resource string, epoch uint64, scopes ...string) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindDelegate, Issuer: org, Gen: gen, Actor: actor,
		EdgeID: edge, Parent: parent, Subject: auth.Identity(auth.OrgOf(subject), auth.NameOf(subject)),
		Tenant: tenant, Resource: resource, Epoch: epoch, Scope: scopes,
	})
}

// DelegateUntil mints an edge with an expiry (inclusive tick bound).
func (b *Builder) DelegateUntil(origin, org string, gen int, actor, edge, parent, subject, tenant, resource string, epoch uint64, notAfter int64, scopes ...string) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindDelegate, Issuer: org, Gen: gen, Actor: actor,
		EdgeID: edge, Parent: parent, Subject: auth.Identity(auth.OrgOf(subject), auth.NameOf(subject)),
		Tenant: tenant, Resource: resource, Epoch: epoch, Scope: scopes, NotAfter: notAfter,
	})
}

// Revoke retires an edge.
func (b *Builder) Revoke(origin, org string, gen int, actor, edge string) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindRevoke, Issuer: org, Gen: gen, Actor: actor,
		EdgeID: edge, EvidenceID: b.NewEvidenceID("rev"),
	})
}

// Leave marks a member as departed, retiring every edge it names.
func (b *Builder) Leave(origin, org string, gen int, member string) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindLeave, Issuer: org, Gen: gen, Actor: member,
		Subject: auth.Identity(org, member), EvidenceID: b.NewEvidenceID("leave"),
	})
}

// Transfer moves a resource to a new owner and epoch.
func (b *Builder) Transfer(origin, org string, gen int, tenant, resource, toOrg string, epoch uint64) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindTransfer, Issuer: org, Gen: gen, Tenant: tenant,
		Resource: resource, ToOrg: toOrg, Epoch: epoch, EvidenceID: b.NewEvidenceID("xfer"),
	})
}

// Ban is an emergency disable.
func (b *Builder) Ban(origin, org string, gen int, tenant, resource, subject, edge, reason string) event.Event {
	return b.Author(origin, event.Event{
		Kind: event.KindBan, Issuer: org, Gen: gen, Tenant: tenant,
		Resource: resource, Subject: subject, EdgeID: edge, Reason: reason,
		EvidenceID: b.NewEvidenceID("ban"),
	})
}

// Clock advances logical time without changing authorization.
func (b *Builder) Clock(origin string) event.Event {
	return b.Author(origin, event.Event{Kind: event.KindClock})
}