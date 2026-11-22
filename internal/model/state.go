// Package model is the pure reference state machine. It folds a canonically
// ordered event set into an authorization state and answers admission queries.
// It performs no I/O, so it can be replayed, diffed, and tested exhaustively.
package model

import (
	"fmt"
	"sort"
	"strings"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
)

// Tenant is a resource namespace owned by one organization.
type Tenant struct {
	ID       string      `json:"id"`
	OwnerOrg string      `json:"owner_org"`
	Source   event.Event `json:"source"`
}

// Resource is a protected object. Epoch increments on every transfer so that
// delegation chains minted under an earlier owner can never become valid again.
type Resource struct {
	Tenant   string      `json:"tenant"`
	ID       string      `json:"id"`
	OwnerOrg string      `json:"owner_org"`
	Epoch    uint64      `json:"epoch"`
	Source   event.Event `json:"source"`
}

// Authority is one credential generation grant: member Actor is allowed to
// delegate under (Issuer, Gen). Admin members may mint root edges.
type Authority struct {
	Issuer string      `json:"issuer"`
	Gen    int         `json:"gen"`
	Member string      `json:"member"`
	Admin  bool        `json:"admin"`
	At     int64       `json:"at"`
	Source event.Event `json:"source"`
}

// Edge is a delegation: Issuer:Actor delegates a scope on a resource to Subject.
type Edge struct {
	ID        string      `json:"id"`
	Issuer    string      `json:"issuer"`
	Gen       int         `json:"gen"`
	Actor     string      `json:"actor"`
	Parent    string      `json:"parent,omitempty"`
	Subject   string      `json:"subject"`
	Tenant    string      `json:"tenant"`
	Resource  string      `json:"resource"`
	Epoch     uint64      `json:"epoch"`
	Scope     []string    `json:"scope"`
	NotBefore int64       `json:"not_before,omitempty"`
	NotAfter  int64       `json:"not_after,omitempty"`
	At        int64       `json:"at"`
	Source    event.Event `json:"source"`
}

// IssuerID is the full identity of the edge's issuer.
func (e Edge) IssuerID() string { return auth.Identity(e.Issuer, e.Actor) }

// Revocation is a retired edge.
type Revocation struct {
	EvidenceID string `json:"evidence_id"`
	EdgeID     string `json:"edge_id"`
	At         int64  `json:"at"`
}

// Departure records that a member left an organization.
type Departure struct {
	EvidenceID string `json:"evidence_id"`
	Subject    string `json:"subject"`
	At         int64  `json:"at"`
}

// Transfer records a resource ownership change.
type Transfer struct {
	EvidenceID string `json:"evidence_id"`
	Tenant     string `json:"tenant"`
	Resource   string `json:"resource"`
	FromOrg    string `json:"from_org"`
	ToOrg      string `json:"to_org"`
	Epoch      uint64 `json:"epoch"`
	At         int64  `json:"at"`
}

// Ban is a permanent emergency disable. It never expires.
type Ban struct {
	EvidenceID string `json:"evidence_id"`
	Issuer     string `json:"issuer"`
	Tick       int64  `json:"tick"`
	Tenant     string `json:"tenant"`
	Resource   string `json:"resource,omitempty"`
	Subject    string `json:"subject,omitempty"`
	EdgeID     string `json:"edge_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// IssuerState isolates one issuer's health and watermark. A quarantined issuer
// can only cause DENY for decisions that depend on it.
type IssuerState struct {
	CurrentGen   int                               `json:"current_gen"`
	Grants       map[int]map[string]*Authority     `json:"grants"`
	Watermark    event.Watermark                   `json:"watermark"`
	Quarantined  bool                              `json:"quarantined"`
	QuarantineBy string                            `json:"quarantine_by,omitempty"`
}

// grant looks up a member's authority under a generation.
func (is *IssuerState) grant(gen int, member string) *Authority {
	if m, ok := is.Grants[gen]; ok {
		return m[member]
	}
	return nil
}

// Grant looks up a member's authority under a generation (exported).
func (is *IssuerState) Grant(gen int, member string) *Authority { return is.grant(gen, member) }

// State is the folded authorization state. All maps/slices are serialized for
// snapshots and are deterministically re-foldable.
type State struct {
	Tenants    map[string]*Tenant              `json:"tenants"`
	Resources  map[string]*Resource            `json:"resources"`
	Issuers    map[string]*IssuerState         `json:"issuers"`
	Edges      map[string]*Edge                `json:"edges"`
	Revoked    map[string]Revocation           `json:"revoked"`
	Left       map[string]Departure            `json:"left"`
	Transfers  map[string][]Transfer           `json:"transfers"`
	Bans       []Ban                           `json:"bans"`
	Evidence   map[string]event.EvidenceRecord `json:"evidence"`
	Watermarks map[string]event.Watermark      `json:"watermarks"`
	Now        int64                           `json:"now"`
}

// New returns an empty state.
func New() *State {
	return &State{
		Tenants:    map[string]*Tenant{},
		Resources:  map[string]*Resource{},
		Issuers:    map[string]*IssuerState{},
		Edges:      map[string]*Edge{},
		Revoked:    map[string]Revocation{},
		Left:       map[string]Departure{},
		Transfers:  map[string][]Transfer{},
		Bans:       []Ban{},
		Evidence:   map[string]event.EvidenceRecord{},
		Watermarks: map[string]event.Watermark{},
	}
}

// ResourceKey returns the canonical lookup key for a resource.
func ResourceKey(tenant, resource string) string { return tenant + "/" + resource }

// issuer returns (creating) the isolated state for an issuer.
func (s *State) issuer(org string) *IssuerState {
	is, ok := s.Issuers[org]
	if !ok {
		is = &IssuerState{
			Grants:    map[int]map[string]*Authority{},
			Watermark: event.Watermark{Issuer: org},
		}
		s.Issuers[org] = is
	}
	return is
}

// Issuer returns the isolated state for an issuer (may be nil).
func (s *State) Issuer(org string) *IssuerState { return s.Issuers[org] }

// advanceWatermark monotonically raises an issuer's watermark.
func (s *State) advanceWatermark(e event.Event) {
	if e.Issuer == "" {
		return
	}
	is := s.issuer(e.Issuer)
	w := event.Watermark{Issuer: e.Issuer, Gen: e.Gen, Tick: e.Tick, Seq: e.Seq}
	if !w.Before(is.Watermark) {
		is.Watermark = w
	}
	if cur, ok := s.Watermarks[e.Issuer]; !ok || cur.Before(w) {
		s.Watermarks[e.Issuer] = w
	}
}

// Quarantine isolates an issuer after a detected fault. It is monotone: an
// issuer never leaves quarantine on its own, and other issuers are unaffected.
func (s *State) Quarantine(org, reason string) {
	is := s.issuer(org)
	is.Quarantined = true
	if is.QuarantineBy == "" {
		is.QuarantineBy = reason
	}
}

// Apply folds one event into the state. It is idempotent so evidence can be
// re-applied after recovery without changing the result.
func (s *State) Apply(e event.Event) error {
	if e.Tick > s.Now {
		s.Now = e.Tick
	}
	s.advanceWatermark(e)

	switch e.Kind {
	case event.KindTenant:
		if _, ok := s.Tenants[e.Tenant]; !ok {
			s.Tenants[e.Tenant] = &Tenant{ID: e.Tenant, OwnerOrg: e.OwnerOrg, Source: e}
		}

	case event.KindResource:
		k := ResourceKey(e.Tenant, e.Resource)
		if _, ok := s.Resources[k]; !ok {
			s.Resources[k] = &Resource{Tenant: e.Tenant, ID: e.Resource, OwnerOrg: e.OwnerOrg, Epoch: 1, Source: e}
		}

	case event.KindAuthority:
		is := s.issuer(e.Issuer)
		if is.Grants[e.Gen] == nil {
			is.Grants[e.Gen] = map[string]*Authority{}
		}
		if _, ok := is.Grants[e.Gen][e.Actor]; !ok {
			is.Grants[e.Gen][e.Actor] = &Authority{
				Issuer: e.Issuer, Gen: e.Gen, Member: e.Actor, Admin: e.Admin, At: e.Tick,
				Source: e,
			}
		}
		if e.Gen > is.CurrentGen {
			is.CurrentGen = e.Gen
		}

	case event.KindRotate:
		is := s.issuer(e.Issuer)
		if is.CurrentGen != 0 && e.FromGen < is.CurrentGen {
			// Stale rotation: harmless replay, ignore.
			return nil
		}
		if is.CurrentGen != 0 && e.FromGen > is.CurrentGen {
			// A rotation that skips the current generation is a per-issuer
			// fault: quarantine only this issuer.
			s.Quarantine(e.Issuer, fmt.Sprintf("rotation gap: from g%d, current g%d", e.FromGen, is.CurrentGen))
			return nil
		}
		if e.ToGen > is.CurrentGen {
			is.CurrentGen = e.ToGen
		}

	case event.KindDelegate:
		if _, ok := s.Edges[e.EdgeID]; ok {
			return nil
		}
		s.Edges[e.EdgeID] = &Edge{
			ID: e.EdgeID, Issuer: e.Issuer, Gen: e.Gen, Actor: e.Actor,
			Parent: e.Parent, Subject: e.Subject, Tenant: e.Tenant,
			Resource: e.Resource, Epoch: e.Epoch, Scope: append([]string(nil), e.Scope...),
			NotBefore: e.NotBefore, NotAfter: e.NotAfter, At: e.Tick, Source: e,
		}

	case event.KindRevoke:
		if _, ok := s.Revoked[e.EdgeID]; !ok {
			s.Revoked[e.EdgeID] = Revocation{EvidenceID: e.EvidenceID, EdgeID: e.EdgeID, At: e.Tick}
		}

	case event.KindLeave:
		if _, ok := s.Left[e.Subject]; !ok {
			s.Left[e.Subject] = Departure{EvidenceID: e.EvidenceID, Subject: e.Subject, At: e.Tick}
		}

	case event.KindTransfer:
		k := ResourceKey(e.Tenant, e.Resource)
		r, ok := s.Resources[k]
		if !ok {
			return fmt.Errorf("transfer: unknown resource %s", k)
		}
		if e.Epoch <= r.Epoch {
			return nil // idempotent / stale
		}
		if e.FromOrg != "" && e.FromOrg != r.OwnerOrg {
			// A transfer that disagrees with the folded owner is a fault of
			// the issuing org only.
			s.Quarantine(e.Issuer, fmt.Sprintf("transfer owner mismatch: event says %s, state %s", e.FromOrg, r.OwnerOrg))
			return nil
		}
		s.Transfers[k] = append(s.Transfers[k], Transfer{
			EvidenceID: e.EvidenceID, Tenant: e.Tenant, Resource: e.Resource,
			FromOrg: r.OwnerOrg, ToOrg: e.ToOrg, Epoch: e.Epoch, At: e.Tick,
		})
		r.OwnerOrg = e.ToOrg
		r.Epoch = e.Epoch

	case event.KindBan:
		for _, b := range s.Bans {
			if b.EvidenceID == e.EvidenceID {
				return nil
			}
		}
		s.Bans = append(s.Bans, Ban{
			EvidenceID: e.EvidenceID, Issuer: e.Issuer, Tick: e.Tick,
			Tenant: e.Tenant, Resource: e.Resource, Subject: e.Subject,
			EdgeID: e.EdgeID, Reason: e.Reason,
		})

	case event.KindClock:
		// Tick already advanced above.
	}

	if e.Evidence() {
		rec := event.FromEvent(e)
		if _, ok := s.Evidence[e.EvidenceID]; !ok {
			s.Evidence[e.EvidenceID] = rec
		}
	}
	return nil
}

// Fold applies a canonical event sequence.
func Fold(events []event.Event) (*State, error) {
	s := New()
	for _, e := range events {
		if err := s.Apply(e); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// ApplyEvidence re-applies retained evidence records. Because Apply is
// idempotent this can safely be run on top of any snapshot, ensuring that a
// stale snapshot can never erase a ban or revocation that was already received.
func (s *State) ApplyEvidence(records []event.EvidenceRecord) {
	sorted := append([]event.EvidenceRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Tick != sorted[j].Tick {
			return sorted[i].Tick < sorted[j].Tick
		}
		return sorted[i].Seq < sorted[j].Seq
	})
	for _, r := range sorted {
		if r.Event.Kind == "" {
			continue
		}
		_ = s.Apply(r.Event)
	}
}

// MergeWatermarks folds additional (e.g. snapshot) watermarks in, taking the
// per-issuer maximum so a restarted node never regresses.
func (s *State) MergeWatermarks(extra map[string]event.Watermark) {
	s.Watermarks = event.MaxWatermarks(s.Watermarks, extra)
	for org, w := range s.Watermarks {
		is := s.issuer(org)
		if is.Watermark.Before(w) {
			is.Watermark = w
		}
	}
}

// MergeEvidence folds retained evidence into state.Evidence.
func (s *State) MergeEvidence(records []event.EvidenceRecord) {
	for _, r := range records {
		if _, ok := s.Evidence[r.EvidenceID]; !ok {
			s.Evidence[r.EvidenceID] = r
		}
	}
}

// EvidenceRecords returns state evidence sorted by EvidenceID.
func (s *State) EvidenceRecords() []event.EvidenceRecord {
	out := make([]event.EvidenceRecord, 0, len(s.Evidence))
	for _, r := range s.Evidence {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EvidenceID < out[j].EvidenceID })
	return out
}

// HasScope reports whether a scope set grants an action.
func HasScope(scope []string, action string) bool {
	for _, s := range scope {
		if s == action || s == "*" {
			return true
		}
	}
	return false
}

// ScopeSubset reports whether child ⊆ parent.
func ScopeSubset(child, parent []string) bool {
	for _, c := range child {
		if !HasScope(parent, c) {
			return false
		}
	}
	return true
}

// joinScope is used in explanations.
func joinScope(scope []string) string {
	if len(scope) == 0 {
		return "-"
	}
	return strings.Join(scope, ",")
}