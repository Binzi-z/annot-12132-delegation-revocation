// Package event defines the canonical, signed, hash-chained records that make
// up a node's durable log. It also provides a minimal evidence journal that is
// retained across compaction.
package event

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"ccrevoke/internal/auth"
)

// Kind enumerates the protocol events.
type Kind string

const (
	// KindTenant registers a tenant and its owning organization.
	KindTenant Kind = "tenant"
	// KindResource registers a resource inside a tenant at an ownership epoch.
	KindResource Kind = "resource"
	// KindAuthority declares an organization authority credential generation.
	KindAuthority Kind = "authority"
	// KindRotate supersedes an issuer credential generation.
	KindRotate Kind = "rotate"
	// KindDelegate issues one delegation edge.
	KindDelegate Kind = "delegate"
	// KindRevoke retires a single delegation edge.
	KindRevoke Kind = "revoke"
	// KindLeave marks a member leaving an organization; every edge that names
	// the member as issuer or subject is retired from the effective tick.
	KindLeave Kind = "leave"
	// KindTransfer moves a resource to a new owning organization and epoch.
	KindTransfer Kind = "transfer"
	// KindBan is an emergency disable. It is monotone and always retained.
	KindBan Kind = "ban"
	// KindClock advances logical time on a node (test/driver convenience).
	KindClock Kind = "clock"
)

// AllKinds lists every event kind, useful for validation and enumeration.
var AllKinds = []Kind{
	KindTenant, KindResource, KindAuthority, KindRotate, KindDelegate,
	KindRevoke, KindLeave, KindTransfer, KindBan, KindClock,
}

// Event is the canonical durable record. Hash and Sig are not part of the
// hashed body but are covered by the chain (Hash includes Sig of prior event
// through Prev).
type Event struct {
	// Envelope
	Node string `json:"node"`
	Seq  uint64 `json:"seq"`
	Tick int64  `json:"tick"`
	Kind Kind   `json:"kind"`

	// Issuer authority (organization) and its credential generation. Node-local
	// kinds (clock) have an empty Issuer.
	Issuer string `json:"issuer,omitempty"`
	Gen    int    `json:"gen,omitempty"`
	// Actor is the member identity that performed the action, or the subject
	// of a leave event.
	Actor string `json:"actor,omitempty"`

	// Payload (kind-specific, flat so the canonical form is unambiguous).
	Tenant     string `json:"tenant,omitempty"`
	Resource   string `json:"resource,omitempty"`
	OwnerOrg   string `json:"owner_org,omitempty"`
	Epoch      uint64 `json:"epoch,omitempty"`
	EdgeID     string `json:"edge_id,omitempty"`
	Parent     string `json:"parent,omitempty"`
	Subject    string `json:"subject,omitempty"`
	Scope      []string `json:"scope,omitempty"`
	NotBefore  int64  `json:"not_before,omitempty"`
	NotAfter   int64  `json:"not_after,omitempty"`
	FromOrg    string `json:"from_org,omitempty"`
	ToOrg      string `json:"to_org,omitempty"`
	FromGen    int    `json:"from_gen,omitempty"`
	ToGen      int    `json:"to_gen,omitempty"`
	Effective  int64  `json:"effective,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// Admin marks an authority declaration as root-capable (able to mint root
	// delegation edges for resources owned by its organization).
	Admin bool `json:"admin,omitempty"`
	// EvidenceID is set on events that must survive compaction.
	EvidenceID string `json:"evidence_id,omitempty"`

	// Chain
	Prev string `json:"prev"`
	Hash string `json:"hash,omitempty"`
	Sig  string `json:"sig"`
}

// body is the canonical hashing form: every field except Hash (Sig is included
// so the chain binds the issuer's signature).
type body struct {
	Node, Kind, Issuer, Actor           string
	Seq, Tick                           int64
	Gen                                 int
	Tenant, Resource, OwnerOrg          string
	Epoch                               uint64
	EdgeID, Parent, Subject, Scope      string
	NotBefore, NotAfter                 int64
	FromOrg, ToOrg                      string
	FromGen, ToGen                      int
	Effective                           int64
	Reason, EvidenceID, Prev, Sig       string
	Admin                               bool
}

func (e *Event) canonicalBody() []byte {
	scope := append([]string(nil), e.Scope...)
	scopeJSON, _ := json.Marshal(scope)
	b := body{
		Node: e.Node, Kind: string(e.Kind), Issuer: e.Issuer, Actor: e.Actor,
		Seq: int64(e.Seq), Tick: e.Tick, Gen: e.Gen,
		Tenant: e.Tenant, Resource: e.Resource, OwnerOrg: e.OwnerOrg,
		Epoch: e.Epoch, EdgeID: e.EdgeID, Parent: e.Parent,
		Subject: e.Subject, Scope: string(scopeJSON),
		NotBefore: e.NotBefore, NotAfter: e.NotAfter,
		FromOrg: e.FromOrg, ToOrg: e.ToOrg, FromGen: e.FromGen, ToGen: e.ToGen,
		Effective: e.Effective, Reason: e.Reason, EvidenceID: e.EvidenceID,
		Prev: e.Prev, Sig: e.Sig, Admin: e.Admin,
	}
	raw, _ := json.Marshal(b)
	return raw
}

// ComputeHash returns the canonical hash of the event body (including Sig).
func (e *Event) ComputeHash() string {
	sum := sha256.Sum256(e.canonicalBody())
	return hex.EncodeToString(sum[:])
}

// SignedPayload is the bytes an issuer signs for this event. It binds the
// envelope, payload, and the previous chain hash, but not the signature itself.
func (e *Event) SignedPayload() []byte {
	c := *e
	c.Sig = ""
	return c.canonicalBody()
}

// SigningIdentity returns the authority identity used to sign the event.
func (e *Event) SigningIdentity() (issuer string, gen int, nodeLocal bool) {
	if e.Issuer == "" {
		return auth.NodeIdentity(e.Node), 0, true
	}
	return e.Issuer, e.Gen, false
}

// Sign attaches the signature and hash. Must be called after Prev is set.
func (e *Event) Sign(reg *auth.Registry) {
	issuer, gen, _ := e.SigningIdentity()
	e.Sig = reg.Sign(issuer, gen, e.SignedPayload())
	e.Hash = e.ComputeHash()
}

// VerifySig checks the issuer signature.
func (e *Event) VerifySig(reg *auth.Registry) bool {
	issuer, gen, _ := e.SigningIdentity()
	return reg.Verify(issuer, gen, e.SignedPayload(), e.Sig)
}

// VerifyHash checks the canonical hash.
func (e *Event) VerifyHash() bool { return e.Hash == e.ComputeHash() }

// Evidence reports whether the event must be retained as revocation evidence.
func (e *Event) Evidence() bool {
	return e.EvidenceID != "" && IsEvidenceKind(e.Kind)
}

// IsEvidenceKind reports which event kinds must be preserved as evidence.
func IsEvidenceKind(k Kind) bool {
	switch k {
	case KindBan, KindRevoke, KindRotate, KindLeave, KindTransfer:
		return true
	}
	return false
}

// EvidenceRecord is the compact, independently checkable kernel of an evidence
// event, plus the full canonical event so a verifier can re-check its
// signature. Evidence records are never removed by compaction; only
// deduplicated.
type EvidenceRecord struct {
	EvidenceID  string `json:"evidence_id"`
	Kind        Kind   `json:"kind"`
	Issuer      string `json:"issuer"`
	Gen         int    `json:"gen"`
	Node        string `json:"node"`
	Seq         uint64 `json:"seq"`
	Tick        int64  `json:"tick"`
	Tenant      string `json:"tenant,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subject     string `json:"subject,omitempty"`
	EdgeID      string `json:"edge_id,omitempty"`
	FromOrg     string `json:"from_org,omitempty"`
	ToOrg       string `json:"to_org,omitempty"`
	FromGen     int    `json:"from_gen,omitempty"`
	ToGen       int    `json:"to_gen,omitempty"`
	Epoch       uint64 `json:"epoch,omitempty"`
	Effective   int64  `json:"effective,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Event       Event  `json:"event"`
}

// DedupKey identifies evidence records that make the same claim. Keeping only
// the record with the highest (Tick, Gen, Seq) per key is the
// "minimal evidence" rule; a later record subsumes an earlier claim about the
// same target.
func (r EvidenceRecord) DedupKey() string {
	switch r.Kind {
	case KindBan:
		// A ban is scoped by its exact target tuple; bans on different targets
		// are distinct claims and must not collapse.
		return "ban|" + r.Issuer + "|" + r.Tenant + "|" + r.Resource + "|" + r.Subject + "|" + r.EdgeID
	case KindRevoke:
		return "revoke|" + r.EdgeID
	case KindRotate:
		// One record per generation transition. Collapsing to the newest
		// rotation would make the recorded chain non-contiguous; replaying a
		// lone "g2->g3" onto a base state that only knows g1 is a false gap.
		// Keeping each from->to step is the minimal set that reconstructs the
		// generation chain.
		return "rotate|" + r.Issuer + "|" + itoaLocal(r.FromGen)
	case KindLeave:
		return "leave|" + r.Subject
	case KindTransfer:
		// Keep only the newest transfer per resource: the highest epoch fully
		// determines the resource's owner and epoch, which is all that chain
		// validity depends on.
		return "transfer|" + r.Tenant + "|" + r.Resource
	}
	return string(r.Kind) + "|" + r.EvidenceID
}

func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// Later reports whether r supersedes o for the same dedup key.
func (r EvidenceRecord) Later(o EvidenceRecord) bool {
	if r.Tick != o.Tick {
		return r.Tick > o.Tick
	}
	if r.Gen != o.Gen {
		return r.Gen > o.Gen
	}
	return r.Seq > o.Seq
}

// FromEvent projects an evidence event into its retained record.
func FromEvent(e Event) EvidenceRecord {
	return EvidenceRecord{
		EvidenceID: e.EvidenceID, Kind: e.Kind, Issuer: e.Issuer, Gen: e.Gen,
		Node: e.Node, Seq: e.Seq, Tick: e.Tick, Tenant: e.Tenant,
		Resource: e.Resource, Subject: e.Subject, EdgeID: e.EdgeID,
		FromOrg: e.FromOrg, ToOrg: e.ToOrg, FromGen: e.FromGen, ToGen: e.ToGen,
		Epoch: e.Epoch, Effective: e.Effective, Reason: e.Reason, Event: e,
	}
}

// MergeEvidence unions two evidence sets and applies the minimal-evidence rule
// (per dedup key keep the latest claim). The result is sorted deterministically.
func MergeEvidence(sets ...[]EvidenceRecord) []EvidenceRecord {
	best := map[string]EvidenceRecord{}
	for _, set := range sets {
		for _, r := range set {
			k := r.DedupKey()
			if prev, ok := best[k]; !ok || r.Later(prev) {
				best[k] = r
			}
		}
	}
	out := make([]EvidenceRecord, 0, len(best))
	for _, r := range best {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EvidenceID < out[j].EvidenceID })
	return out
}

// Watermark is a per-issuer monotone observation point: the highest
// (generation, tick, seq) ever seen from an issuer. It is migratable: it is
// serialized in snapshots and carried forward across restart and compaction.
type Watermark struct {
	Issuer string `json:"issuer"`
	Gen    int    `json:"gen"`
	Tick   int64  `json:"tick"`
	Seq    uint64 `json:"seq"`
}

// Before reports whether w is strictly older than o.
func (w Watermark) Before(o Watermark) bool {
	if w.Gen != o.Gen {
		return w.Gen < o.Gen
	}
	if w.Tick != o.Tick {
		return w.Tick < o.Tick
	}
	return w.Seq < o.Seq
}

// MaxWatermarks merges per-issuer watermarks, taking the maximum. This is how a
// recovering node prevents its watermark from regressing below one it already
// published.
func MaxWatermarks(a, b map[string]Watermark) map[string]Watermark {
	out := make(map[string]Watermark, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if cur, ok := out[k]; !ok || cur.Before(v) {
			out[k] = v
		}
	}
	return out
}

// ErrChain links chain verification errors.
var ErrChain = errors.New("event: chain broken")

// VerifyChain checks sequential hashes and signatures of a canonical order.
func VerifyChain(events []Event, reg *auth.Registry) error {
	prev := ""
	for _, e := range events {
		if e.Prev != prev {
			return fmt.Errorf("%w at seq %d/%d: prev %q want %q", ErrChain, e.Seq, e.Tick, e.Prev, prev)
		}
		if !e.VerifyHash() {
			return fmt.Errorf("%w at seq %d/%d: hash mismatch", ErrChain, e.Seq, e.Tick)
		}
		if !e.VerifySig(reg) {
			return fmt.Errorf("%w at seq %d/%d: bad signature", ErrChain, e.Seq, e.Tick)
		}
		prev = e.Hash
	}
	return nil
}

// CanonicalOrder sorts events by logical time, node, then sequence. Both nodes
// fold the same replicated set in this order, giving deterministic replay.
func CanonicalOrder(events []Event) {
	sort.SliceStable(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if a.Tick != b.Tick {
			return a.Tick < b.Tick
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Seq < b.Seq
	})
}

// Encode renders an event as canonical single-line JSON.
func Encode(e Event) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Decode parses a canonical JSON line.
func Decode(line []byte) (Event, error) {
	var e Event
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Event{}, err
	}
	return e, nil
}

// Validate performs structural checks used before an event is applied.
func (e *Event) Validate() error {
	if e.Node == "" {
		return errors.New("event: empty node")
	}
	if e.Seq == 0 {
		return errors.New("event: zero seq")
	}
	switch e.Kind {
	case KindTenant:
		if e.Tenant == "" || e.OwnerOrg == "" || e.Issuer != e.OwnerOrg {
			return errors.New("tenant: needs tenant, owner org and owner-signed issuer")
		}
	case KindResource:
		if e.Tenant == "" || e.Resource == "" || e.OwnerOrg == "" || e.Issuer != e.OwnerOrg {
			return errors.New("resource: needs tenant, resource, owner org and owner-signed issuer")
		}
	case KindAuthority:
		if e.Issuer == "" || e.Gen <= 0 || e.Actor == "" {
			return errors.New("authority: needs issuer, generation and member")
		}
	case KindRotate:
		if e.Issuer == "" || e.FromGen <= 0 || e.ToGen <= e.FromGen {
			return errors.New("rotate: needs increasing generations")
		}
	case KindDelegate:
		if e.Issuer == "" || e.Gen <= 0 || e.EdgeID == "" || e.Actor == "" || e.Subject == "" {
			return errors.New("delegate: needs issuer, gen, edge id, actor, subject")
		}
		if !auth.ValidIdentity(e.Subject) {
			return errors.New("delegate: malformed subject identity")
		}
		if e.Tenant == "" || e.Resource == "" || len(e.Scope) == 0 {
			return errors.New("delegate: needs tenant, resource, scope")
		}
		if e.NotAfter != 0 && e.NotAfter < e.NotBefore {
			return errors.New("delegate: invalid validity window")
		}
	case KindRevoke:
		if e.EdgeID == "" || e.EvidenceID == "" {
			return errors.New("revoke: needs edge id and evidence id")
		}
	case KindLeave:
		if e.Subject == "" || e.EvidenceID == "" {
			return errors.New("leave: needs member identity and evidence id")
		}
	case KindTransfer:
		if e.Tenant == "" || e.Resource == "" || e.ToOrg == "" || e.EvidenceID == "" {
			return errors.New("transfer: needs tenant, resource, target org, evidence id")
		}
	case KindBan:
		if e.EvidenceID == "" || e.Tenant == "" {
			return errors.New("ban: needs evidence id and tenant")
		}
		if e.Subject == "" && e.EdgeID == "" && e.Resource == "" {
			return errors.New("ban: needs subject, edge or resource target")
		}
	case KindClock:
		if e.Issuer != "" {
			return errors.New("clock: must be node-local")
		}
	default:
		return fmt.Errorf("event: unknown kind %q", e.Kind)
	}
	return nil
}

// String renders a short human description used in per-decision explanations.
func (e Event) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s@%d#%d", e.Kind, e.Tick, e.Seq)
	switch e.Kind {
	case KindDelegate:
		fmt.Fprintf(&b, "(%s->%s %s/%s gen=%d)", e.Actor, e.Subject, e.Tenant, e.Resource, e.Gen)
	case KindBan:
		fmt.Fprintf(&b, "(target=%s edge=%s tenant=%s ev=%s)", e.Subject, e.EdgeID, e.Tenant, e.EvidenceID)
	case KindRevoke:
		fmt.Fprintf(&b, "(edge=%s ev=%s)", e.EdgeID, e.EvidenceID)
	case KindLeave:
		fmt.Fprintf(&b, "(member=%s ev=%s)", e.Subject, e.EvidenceID)
	case KindRotate:
		fmt.Fprintf(&b, "(%s g%d->g%d)", e.Issuer, e.FromGen, e.ToGen)
	case KindTransfer:
		fmt.Fprintf(&b, "(%s/%s %s->%s epoch=%d ev=%s)", e.Tenant, e.Resource, e.FromOrg, e.ToOrg, e.Epoch, e.EvidenceID)
	}
	return b.String()
}