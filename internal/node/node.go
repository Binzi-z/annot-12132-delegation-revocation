// Package node implements the two-node protocol service: event authoring,
// replication, issuer isolation, watermarks, compaction, and admission with
// certificates.
package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/store"
)

// Config configures a node.
type Config struct {
	Org   string // organization this node belongs to and authors under
	Dir   string // durable directory
	Peers []string // peer orgs this node replicates with
	Seed  string   // shared key seed
	// TickStep is how much logical time advances per authored event when the
	// caller does not set an explicit tick. Kept > 0 so expiry is observable.
	TickStep int64
}

// Node is a running protocol node.
type Node struct {
	cfg Config
	reg *auth.Registry
	st  *store.Store

	mu      sync.Mutex
	state   *model.State
	clock   int64

	peerMu  sync.Mutex
	peerErr map[string]string // org -> last replication error (isolation diagnostics)
}

// Open loads a node from disk.
func Open(cfg Config) (*Node, error) {
	if cfg.Org == "" {
		return nil, errors.New("node: org required")
	}
	if cfg.TickStep <= 0 {
		cfg.TickStep = 1
	}
	st, err := store.Open(cfg.Dir)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:     cfg,
		reg:     auth.NewRegistry(cfg.Seed),
		st:      st,
		peerErr: map[string]string{},
	}
	if err := n.rebuild(); err != nil {
		st.Close()
		return nil, err
	}
	return n, nil
}

// Close releases the store.
func (n *Node) Close() error { return n.st.Close() }

// Org returns this node's organization.
func (n *Node) Org() string { return n.cfg.Org }

// Registry returns the shared key registry (public inputs only).
func (n *Node) Registry() *auth.Registry { return n.reg }

// State returns a deep-ish copy of the folded state under lock, for queries.
func (n *Node) stateCopy() *model.State {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state
}

// rebuild folds all retained events plus the snapshot, then re-applies the
// durable evidence union so a stale snapshot can never subtract a ban.
func (n *Node) rebuild() error {
	snap := n.st.Snapshot()
	var st *model.State
	if snap != nil {
		st = model.New()
		if err := json.Unmarshal(snap.State, st); err != nil {
			return fmt.Errorf("node: snapshot state: %w", err)
		}
		if st.Evidence == nil {
			st.Evidence = map[string]event.EvidenceRecord{}
		}
		if st.Watermarks == nil {
			st.Watermarks = map[string]event.Watermark{}
		}
		st.MergeWatermarks(snap.Watermarks)
		// Durable evidence journal is authoritative on recovery.
		st.ApplyEvidence(n.st.Evidence())
	} else {
		var err error
		st, err = model.Fold(n.st.Events())
		if err != nil {
			return err
		}
		// Even without a snapshot, the durable evidence journal is the union of
		// everything ever accepted, including any retained-only records.
		st.ApplyEvidence(n.st.Evidence())
	}
	n.state = st
	n.clock = st.Now
	return nil
}

// Clock returns logical time.
func (n *Node) Clock() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.clock
}

// AdvanceClock advances logical time by dticks.
func (n *Node) AdvanceClock(dticks int64) (int64, error) {
	ev, err := n.Author(AuthorInput{Kind: event.KindClock, Tick: n.Clock() + dticks})
	if err != nil {
		return 0, err
	}
	return ev.Tick, nil
}

// AuthorInput describes a locally-authored event. The Node fills in origin,
// sequence, issuer, and signing.
type AuthorInput struct {
	Kind     event.Kind
	Tick     int64 // if 0, derived from the logical clock
	Issuer   string
	Gen      int
	Actor    string
	Tenant   string
	Resource string
	OwnerOrg string
	Epoch    uint64
	EdgeID   string
	Parent   string
	Subject  string
	Scope    []string
	NotBefore int64
	NotAfter  int64
	FromOrg  string
	ToOrg    string
	FromGen  int
	ToGen    int
	Effective int64
	Reason   string
	EvidenceID string
	Admin    bool
}

// Author appends a locally-authored event, durably, and folds it. It returns
// the stored event. If the input is invalid for this node's authority it is
// rejected before any write.
func (n *Node) Author(in AuthorInput) (event.Event, error) {
	n.mu.Lock()
	// Hold the lock across authoring so origin sequence allocation and the
	// clock stay consistent with the applied state.
	defer n.mu.Unlock()

	tick := in.Tick
	if tick == 0 {
		n.clock += n.cfg.TickStep
		tick = n.clock
	} else if tick > n.clock {
		n.clock = tick
	}

	ev := event.Event{
		Node: n.cfg.Org, Seq: n.st.NextSeq(n.cfg.Org), Tick: tick, Kind: in.Kind,
		Issuer: in.Issuer, Gen: in.Gen, Actor: in.Actor,
		Tenant: in.Tenant, Resource: in.Resource, OwnerOrg: in.OwnerOrg,
		Epoch: in.Epoch, EdgeID: in.EdgeID, Parent: in.Parent, Subject: in.Subject,
		Scope: in.Scope, NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		FromOrg: in.FromOrg, ToOrg: in.ToOrg, FromGen: in.FromGen, ToGen: in.ToGen,
		Effective: in.Effective, Reason: in.Reason, EvidenceID: in.EvidenceID,
		Admin: in.Admin,
	}
	if ev.Kind != event.KindClock && ev.Issuer == "" {
		ev.Issuer = n.cfg.Org
	}
	if ev.Evidence() == false && event.IsEvidenceKind(ev.Kind) && ev.EvidenceID == "" {
		ev.EvidenceID = fmt.Sprintf("%s-%s-%d", ev.Issuer, strings.ToLower(string(ev.Kind)), ev.Seq)
	}
	if err := n.authorizeLocal(ev); err != nil {
		return event.Event{}, err
	}
	ev.Prev = n.prevFor(n.cfg.Org)
	if err := ev.Validate(); err != nil {
		return event.Event{}, err
	}
	ev.Sign(n.reg)
	if _, err := n.st.Append(ev); err != nil {
		return event.Event{}, err
	}
	if err := n.state.Apply(ev); err != nil {
		return event.Event{}, err
	}
	return ev, nil
}

// prevFor returns the previous event hash in the local origin chain, which is
// the highest-sequence event already accepted from this origin.
func (n *Node) prevFor(origin string) string {
	if origin == n.cfg.Org {
		if m, ok := n.st.OriginMark(origin); ok {
			return m.Hash
		}
		return ""
	}
	if m, ok := n.st.OriginMark(origin); ok {
		return m.Hash
	}
	return ""
}

// authorizeLocal enforces that a node only authors events under its own org
// and, for delegation, with a credential generation it currently holds.
// Administrative evidence acts (ban, revoke, leave, transfer, rotate) are
// issued by the organization itself, so they need no delegation grant; they
// still may not use a stale generation.
func (n *Node) authorizeLocal(ev event.Event) error {
	if ev.Kind == event.KindClock {
		return nil
	}
	if ev.Issuer != n.cfg.Org {
		return fmt.Errorf("node %s may not author issuer %q", n.cfg.Org, ev.Issuer)
	}
	if ev.Kind == event.KindAuthority {
		return nil
	}
	is := n.state.Issuers[ev.Issuer]
	cur := 0
	if is != nil {
		cur = is.CurrentGen
	}
	if ev.Gen > 0 && cur != 0 && ev.Gen != cur {
		return fmt.Errorf("stale generation: authored g%d, current g%d", ev.Gen, cur)
	}
	if ev.Kind == event.KindDelegate {
		if is == nil || is.Grant(ev.Gen, ev.Actor) == nil {
			return fmt.Errorf("actor %q has no authority at %s g%d", ev.Actor, ev.Issuer, ev.Gen)
		}
	}
	return nil
}

// Ingest accepts an event authored by a peer. It is the replication entry point
// and applies strict per-origin failure isolation.
func (n *Node) Ingest(ev event.Event) error {
	if ev.Node == n.cfg.Org {
		return errors.New("ingest: event is locally authored; use Author")
	}
	if !ev.VerifySig(n.reg) {
		return fmt.Errorf("ingest: invalid signature from %s seq %d", ev.Node, ev.Seq)
	}
	if !ev.VerifyHash() {
		return fmt.Errorf("ingest: invalid hash from %s seq %d", ev.Node, ev.Seq)
	}
	if err := ev.Validate(); err != nil {
		return fmt.Errorf("ingest: invalid event from %s seq %d: %w", ev.Node, ev.Seq, err)
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// Gap detection: if we are missing a predecessor, flag that origin and
	// refuse to apply out of order. Isolation: only this origin is affected.
	if ev.Seq > 1 && n.st.NextSeq(ev.Node) < ev.Seq {
		n.isolate(ev.Node, fmt.Sprintf("replication gap at seq %d", ev.Seq))
		return fmt.Errorf("ingest: gap for %s at seq %d", ev.Node, ev.Seq)
	}
	if !n.chainLinkOK(ev) {
		n.isolate(ev.Node, fmt.Sprintf("origin chain mismatch at seq %d", ev.Seq))
		return fmt.Errorf("ingest: %s seq %d does not extend its origin chain", ev.Node, ev.Seq)
	}

	_, err := n.st.Append(ev)
	if errors.Is(err, store.ErrDuplicate) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := n.state.Apply(ev); err != nil {
		// A malformed payload that passed structure checks is an issuer fault:
		// isolate the originating org, keep the event as evidence if it is one.
		n.isolate(ev.Issuer, err.Error())
		return err
	}
	return nil
}

func (n *Node) chainLinkOK(ev event.Event) bool {
	if ev.Seq <= 1 {
		return ev.Prev == ""
	}
	mark, ok := n.st.OriginMark(ev.Node)
	if !ok {
		return false
	}
	if ev.Seq == mark.Seq+1 {
		return ev.Prev == mark.Hash
	}
	// Older event: we cannot cheaply verify its predecessor here, but the store
	// dedupes by (origin, seq, hash), so accept it for replay.
	return true
}

// isolate quarantines an issuer in the live state. It never blocks other
// issuers and never deletes evidence.
func (n *Node) isolate(org, reason string) {
	n.state.Quarantine(org, reason)
	n.peerMu.Lock()
	n.peerErr[org] = reason
	n.peerMu.Unlock()
}

// PeerErrors returns the last observed fault per peer org.
func (n *Node) PeerErrors() map[string]string {
	n.peerMu.Lock()
	defer n.peerMu.Unlock()
	out := make(map[string]string, len(n.peerErr))
	for k, v := range n.peerErr {
		out[k] = v
	}
	return out
}

// Quarantined returns the quarantined issuers and their reasons.
func (n *Node) Quarantined() map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[string]string{}
	for org, is := range n.state.Issuers {
		if is.Quarantined {
			out[org] = is.QuarantineBy
		}
	}
	return out
}

// EventsSince returns events accepted locally with peer origin, for
// replication. The returned slice is ordered by origin then seq.
func (n *Node) EventsSince(origin string, afterSeq uint64) []event.Event {
	var out []event.Event
	for _, e := range n.st.Events() {
		if e.Node == origin && e.Seq > afterSeq {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out
}

// AllEvents returns a copy of every retained event.
func (n *Node) AllEvents() []event.Event { return n.st.Events() }

// StateDigest returns a stable JSON digest of the authorization-relevant state,
// used by tests to compare two nodes.
func (n *Node) StateDigest() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	dig := struct {
		Revoked   map[string]model.Revocation
		Left      map[string]model.Departure
		Bans      []model.Ban
		Watermark map[string]event.Watermark
		CurrentGen map[string]int
	}{n.state.Revoked, n.state.Left, n.state.Bans, n.state.Watermarks, map[string]int{}}
	for org, is := range n.state.Issuers {
		dig.CurrentGen[org] = is.CurrentGen
	}
	raw, _ := json.Marshal(dig)
	return string(raw)
}

// Evaluate answers an admission query and returns both the decision and a
// portable certificate.
func (n *Node) Evaluate(req model.Request) (model.Decision, *proto.Certificate) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if req.NodeOrg == "" {
		req.NodeOrg = n.cfg.Org
	}
	d := n.state.Evaluate(req)
	cert := proto.FromDecision(n.state, d, req, n.cfg.Org, n.reg)
	return d, cert
}

// Checkpoint compacts this node's durable store into a snapshot and retained
// evidence.
func (n *Node) Checkpoint() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	raw, err := json.Marshal(n.state)
	if err != nil {
		return err
	}
	return n.st.Checkpoint(raw, n.state.Watermarks)
}

// Evidence returns the node's durable evidence union.
func (n *Node) Evidence() []event.EvidenceRecord { return n.st.Evidence() }

// Watermarks returns the node's per-issuer watermarks.
func (n *Node) Watermarks() map[string]event.Watermark {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make(map[string]event.Watermark, len(n.state.Watermarks))
	for k, v := range n.state.Watermarks {
		out[k] = v
	}
	return out
}

// MergePeerEvidence ingests evidence records a peer advertises. This is how a
// ban received on one node propagates and remains durable on the other; it is
// idempotent and never lowers a watermark.
func (n *Node) MergePeerEvidence(records []event.EvidenceRecord) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var errs []string
	for _, r := range records {
		if r.Event.Kind == "" {
			continue
		}
		if !r.Event.VerifySig(n.reg) || !r.Event.VerifyHash() {
			errs = append(errs, "bad evidence "+r.EvidenceID)
			continue
		}
		if r.Event.Node == n.cfg.Org {
			continue
		}
		if _, err := n.st.Append(r.Event); err != nil && !errors.Is(err, store.ErrDuplicate) {
			errs = append(errs, err.Error())
			continue
		}
		if err := n.state.Apply(r.Event); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("evidence merge: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Now returns a timestamp used only for diagnostics (never in signed logic).
func Now() int64 { return time.Now().UnixNano() }