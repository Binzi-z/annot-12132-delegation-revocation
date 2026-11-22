// Package interleave is the small reference state machine that enumerates
// interleavings of reauthorization, ownership transfer, expiry, compaction and
// restart, checking the revocation protocol invariants on every reachable
// state.
package interleave

import (
	"fmt"
	"sort"
	"strings"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/scenario"
)

// Invariant names.
const (
	InvIndependentPath     = "independent-path"
	InvRevokedStaysDead    = "revoked-stays-dead"
	InvBanMonotone         = "ban-monotone"
	InvNonRevokedStaysLive = "non-revoked-stays-live"
	// InvExpiryHonored: an edge past its NotAfter never authorizes and, once it
	// is the only path, the subject is denied.
	InvExpiryHonored     = "expiry-honored"
	InvCertificateVerify = "certificate-verify"
)

// ActionKind enumerates the interleaving alphabet.
type ActionKind string

const (
	ActRevokeEdge  ActionKind = "revoke-edge"
	ActRotate      ActionKind = "rotate"
	ActReauthorize ActionKind = "reauthorize"
	ActTransfer    ActionKind = "transfer"
	ActExpire      ActionKind = "expire"
	ActBan         ActionKind = "ban"
	ActCompact     ActionKind = "compaction"
	ActRestart     ActionKind = "restart"
	ActSwitchPath  ActionKind = "switch-path"
)

// Action is one named transition. Apply receives a clone of the machine and
// mutates it; the enumerator diffs invariants before/after.
type Action struct {
	Kind  ActionKind
	Label string
	// OneDoorHash makes actions comparable across machines.
	Apply func(m *Machine)
}

// Machine holds a canonical event log and abstracts compaction/restart on it.
type Machine struct {
	Reg      *auth.Registry
	Log      []event.Event
	State    *model.State
	Evidence []event.EvidenceRecord
	SnapAt   int
	Now      int64
	Events   *scenario.Builder
}

// New builds the canonical two-chain world.
func New() *Machine {
	f := scenario.NewFixture()
	m := &Machine{Reg: f.Reg, Log: append([]event.Event(nil), f.B.Events...), Events: f.B}
	m.fold()
	return m
}

func (m *Machine) fold() {
	st, err := model.Fold(m.Log)
	if err != nil {
		panic(err)
	}
	st.ApplyEvidence(m.Evidence)
	m.State = st
	m.Now = st.Now
}

// Clone deep-copies the machine (events are immutable value types).
func (m *Machine) Clone() *Machine {
	c := &Machine{
		Reg: m.Reg, Log: append([]event.Event(nil), m.Log...),
		Evidence: append([]event.EvidenceRecord(nil), m.Evidence...),
		SnapAt: m.SnapAt, Now: m.Now, Events: m.Events,
	}
	c.fold()
	return c
}

// Append adds an event and refolds. Evidence is refreshed from the log.
func (m *Machine) Append(e event.Event) {
	m.Log = append(m.Log, e)
	m.fold()
	m.refreshEvidence()
}

func (m *Machine) refreshEvidence() {
	recs := make([]event.EvidenceRecord, 0)
	for _, e := range m.Log {
		if e.Evidence() {
			recs = append(recs, event.FromEvent(e))
		}
	}
	m.Evidence = event.MergeEvidence(m.Evidence, recs)
}

// Compact simulates compaction: the snapshot now covers the whole log, but all
// evidence is retained.
func (m *Machine) Compact() { m.SnapAt = len(m.Log) }

// Restart simulates recovery. A stale snapshot would carry state as of SnapAt;
// correctness demands the durable evidence journal restore every ban/revoke
// that happened after SnapAt. We model the worst case by re-folding only the
// pre-snapshot prefix, then applying the durable evidence union.
func (m *Machine) Restart() {
	prefix := m.Log
	if m.SnapAt > 0 && m.SnapAt < len(m.Log) {
		prefix = m.Log[:m.SnapAt]
	}
	st, err := model.Fold(prefix)
	if err != nil {
		panic(err)
	}
	st.ApplyEvidence(m.Evidence)
	m.State = st
	m.Now = st.Now
}

// Evaluate runs a LOCAL admission query on tenant-a/doc-a.
func (m *Machine) Evaluate(subject, action string) model.Decision {
	return m.State.Evaluate(model.Request{
		Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subject,
		Action: action, Class: model.AccessLocal, NodeOrg: scenario.OrgA,
	})
}

// Observation is the invariant-relevant projection of a state.
type Observation struct {
	BobsAllowed  bool // bob has an independent path (chain1)
	CarlAllowed  bool // carl has an independent path (chain2)
	ErinAllowed  bool // erin has an expiring path (minted+expired by action)
	BobPath      string
	BanCount     int // raw ban records
	RevokedCount int
	// Claims is the set of distinct evidence *claims* (dedup keys), not raw
	// evidence ids: the minimal-evidence rule may replace an earlier record for
	// the same claim with a later one, which must not count as evidence loss.
	Claims []string
	// BanClaims and RevokeClaims are the claim subsets for bans and revocations.
	BanClaims    []string
	RevokeClaims []string
	Digest       string
}

// Observe projects the state.
func (m *Machine) Observe() Observation {
	bob := m.Evaluate(scenario.Id(scenario.OrgB, scenario.Bob), "read")
	carl := m.Evaluate(scenario.Id(scenario.OrgB, scenario.Carl), "read")
	erin := m.Evaluate(scenario.Id(scenario.OrgB, scenario.Erin), "read")
	obs := Observation{
		BobsAllowed: bob.Allowed, CarlAllowed: carl.Allowed, ErinAllowed: erin.Allowed,
		BobPath: bob.ChainID, BanCount: len(m.State.Bans),
		RevokedCount: len(m.State.Revoked),
	}
	claims := map[string]bool{}
	banClaims := map[string]bool{}
	revokeClaims := map[string]bool{}
	add := func(r event.EvidenceRecord) {
		claims[r.DedupKey()] = true
		switch r.Kind {
		case event.KindBan:
			banClaims[r.DedupKey()] = true
		case event.KindRevoke:
			revokeClaims[r.DedupKey()] = true
		}
	}
	for _, r := range m.Evidence {
		add(r)
	}
	for _, r := range m.State.Evidence {
		add(r)
	}
	for k := range claims {
		obs.Claims = append(obs.Claims, k)
	}
	for k := range banClaims {
		obs.BanClaims = append(obs.BanClaims, k)
	}
	for k := range revokeClaims {
		obs.RevokeClaims = append(obs.RevokeClaims, k)
	}
	sort.Strings(obs.Claims)
	sort.Strings(obs.BanClaims)
	sort.Strings(obs.RevokeClaims)
	var b strings.Builder
	keys := make([]string, 0, len(m.State.Revoked))
	for k := range m.State.Revoked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(&b, "revoked=%s;claims=%s", strings.Join(keys, ","), strings.Join(obs.Claims, ","))
	obs.Digest = b.String()
	return obs
}

// Violation is one broken invariant.
type Violation struct {
	Invariant string
	Path      string // action labels
	Detail    string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Invariant, v.Path, v.Detail)
}