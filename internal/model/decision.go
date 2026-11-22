package model

import (
	"fmt"
	"sort"
	"strings"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
)

// AccessClass is the category of an access decision. The class determines how
// a partition of an issuer affects the verdict (see Evaluate).
type AccessClass string

const (
	// AccessLocal is an access to a resource currently owned by the deciding
	// node's own organization. The owner's durable state is authoritative;
	// chains that cross into a partitioned org are still evaluated against the
	// evidence already durably recorded locally, so independent chains keep
	// working while the node is partitioned.
	AccessLocal AccessClass = "LOCAL"
	// AccessRemoteRead is a read of another org's resource. A chain requiring an
	// issuer that is unreachable at decision time is refused (no stale
	// cross-boundary reads). Chains whose issuers are all reachable continue.
	AccessRemoteRead AccessClass = "REMOTE_READ"
	// AccessRemoteWrite is a mutation of another org's resource. While the owner
	// org is partitioned the decision fails closed regardless of cached data.
	AccessRemoteWrite AccessClass = "REMOTE_WRITE"
)

// Request is an admission query against the folded state.
type Request struct {
	Tenant   string      `json:"tenant"`
	Resource string      `json:"resource"`
	Subject  string      `json:"subject"`
	Action   string      `json:"action"`
	Class    AccessClass `json:"class"`
	NodeOrg  string      `json:"node_org"`
	// Unreachable lists issuer orgs the deciding node cannot currently reach.
	// The node's own org is always reachable.
	Unreachable []string `json:"unreachable,omitempty"`
}

// ChainStep is the per-edge evaluation recorded in a decision and certificate.
type ChainStep struct {
	EdgeID    string   `json:"edge_id"`
	Parent    string   `json:"parent,omitempty"`
	Issuer    string   `json:"issuer"`
	Gen       int      `json:"gen"`
	Actor     string   `json:"actor"`
	Subject   string   `json:"subject"`
	Scope     []string `json:"scope"`
	Epoch     uint64   `json:"epoch"`
	Valid     bool     `json:"valid"`
	Reasons   []string `json:"reasons,omitempty"`
	Freshness string   `json:"freshness,omitempty"`
}

// Chain is one root-to-subject delegation path.
type Chain struct {
	ID    string      `json:"id"`
	Steps []ChainStep `json:"steps"`
	// Valid reports whether authorization-valid (ignoring partition policy).
	Valid bool `json:"valid"`
	// Usable reports whether the chain is usable under the request's class and
	// partition state.
	Usable  bool     `json:"usable"`
	Reasons []string `json:"reasons,omitempty"`
}

// Decision is the full, auditable answer to a Request.
type Decision struct {
	Allowed  bool        `json:"allowed"`
	Class    AccessClass `json:"class"`
	Tenant   string      `json:"tenant"`
	Resource string      `json:"resource"`
	Subject  string      `json:"subject"`
	Action   string      `json:"action"`
	NodeOrg  string      `json:"node_org"`

	ResourceOwner string `json:"resource_owner,omitempty"`
	ResourceEpoch uint64 `json:"resource_epoch,omitempty"`

	ChainID  string `json:"chain_id,omitempty"`
	Chains   []Chain `json:"chains,omitempty"`
	Reasons  []string `json:"reasons,omitempty"`

	EvidenceIDs []string                    `json:"evidence_ids,omitempty"`
	Watermarks  map[string]event.Watermark  `json:"watermarks,omitempty"`
	Now         int64                       `json:"now"`
}

// Explain renders a compact human-readable explanation.
func (d Decision) Explain() string {
	var b strings.Builder
	verdict := "DENY"
	if d.Allowed {
		verdict = "ALLOW"
	}
	fmt.Fprintf(&b, "%s %s %s by %s on %s/%s (class=%s owner=%s epoch=%d)\n",
		verdict, d.Subject, d.Action, d.NodeOrg, d.Tenant, d.Resource, d.Class, d.ResourceOwner, d.ResourceEpoch)
	if d.ChainID != "" {
		fmt.Fprintf(&b, "  chain=%s\n", d.ChainID)
	}
	for _, r := range d.Reasons {
		fmt.Fprintf(&b, "  reason: %s\n", r)
	}
	for _, c := range d.Chains {
		state := "invalid"
		if c.Usable {
			state = "usable"
		} else if c.Valid {
			state = "valid-but-unusable"
		}
		fmt.Fprintf(&b, "  candidate %s [%s]%s\n", c.ID, state, chainReasonSuffix(c.Reasons))
		for _, s := range c.Steps {
			st := "ok"
			if !s.Valid {
				st = "FAIL"
			}
			fmt.Fprintf(&b, "    %-4s %s gen=%d %s->%s scope=%s epoch=%d %s\n",
				st, s.EdgeID, s.Gen, auth.Identity(s.Issuer, s.Actor), s.Subject,
				joinScope(s.Scope), s.Epoch, strings.Join(s.Reasons, "; "))
		}
	}
	if len(d.EvidenceIDs) > 0 {
		fmt.Fprintf(&b, "  evidence: %s\n", strings.Join(d.EvidenceIDs, ","))
	}
	return b.String()
}

func chainReasonSuffix(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	return " " + strings.Join(reasons, "; ")
}

// unreachableSet builds the partition set, always excluding the node's org.
func unreachableSet(req Request) map[string]bool {
	out := map[string]bool{}
	for _, org := range req.Unreachable {
		if org != "" && org != req.NodeOrg {
			out[org] = true
		}
	}
	return out
}

// Evaluate answers a request against the state. It never mutates the state.
func (s *State) Evaluate(req Request) Decision {
	d := Decision{
		Class: req.Class, Tenant: req.Tenant, Resource: req.Resource,
		Subject: req.Subject, Action: req.Action, NodeOrg: req.NodeOrg,
		Now: s.Now, Watermarks: map[string]event.Watermark{},
	}

	k := ResourceKey(req.Tenant, req.Resource)
	res, ok := s.Resources[k]
	if !ok {
		d.Reasons = append(d.Reasons, "unknown resource")
		return d
	}
	d.ResourceOwner = res.OwnerOrg
	d.ResourceEpoch = res.Epoch

	part := unreachableSet(req)

	// Class sanity: LOCAL requires the deciding node to own the resource; a
	// remote class requires it not to (otherwise the caller is confused about
	// who is authoritative and we fail closed).
	switch req.Class {
	case AccessLocal:
		if res.OwnerOrg != req.NodeOrg {
			d.Reasons = append(d.Reasons, "LOCAL class but resource owner is "+res.OwnerOrg)
			s.appendEvidenceForTenant(&d, req)
			return d
		}
	case AccessRemoteRead, AccessRemoteWrite:
		if res.OwnerOrg == req.NodeOrg {
			d.Reasons = append(d.Reasons, string(req.Class)+" class but deciding node owns the resource; use LOCAL")
			s.appendEvidenceForTenant(&d, req)
			return d
		}
	default:
		d.Reasons = append(d.Reasons, "unknown access class")
		return d
	}

	// Fail-closed rule: a remote write while the owner org is unreachable is
	// denied outright, regardless of cached evidence.
	if req.Class == AccessRemoteWrite && part[res.OwnerOrg] {
		d.Reasons = append(d.Reasons, "REMOTE_WRITE denied: owner org "+res.OwnerOrg+" is partitioned")
		s.appendEvidenceForTenant(&d, req)
		return d
	}

	chains := s.candidateChains(res, req.Subject)
	if len(chains) == 0 {
		d.Reasons = append(d.Reasons, "no delegation path reaches subject")
		s.appendEvidenceForTenant(&d, req)
		return d
	}

	var usable *Chain
	for i := range chains {
		c := &chains[i]
		s.evaluateChain(res, c)
		s.applyClassPolicy(req, part, c)
		if c.Usable && (usable == nil || betterChain(c, usable)) {
			usable = c
		}
	}
	sortChains(chains)
	d.Chains = chains
	s.appendEvidenceForChains(&d, res, chains)

	if usable == nil {
		d.Reasons = append(d.Reasons, "no usable delegation path")
		return d
	}

	if !HasScope(usable.Steps[len(usable.Steps)-1].Scope, req.Action) {
		d.Reasons = append(d.Reasons, fmt.Sprintf("chosen path scope %s does not grant %q",
			joinScope(usable.Steps[len(usable.Steps)-1].Scope), req.Action))
		usable.Usable = false
		return d
	}

	d.Allowed = true
	d.ChainID = usable.ID
	d.Watermarks = s.chainWatermarks(usable)
	return d
}

// betterChain prefers shorter chains, then lexicographically smaller ids, to
// make the choice deterministic.
func betterChain(a, b *Chain) bool {
	if len(a.Steps) != len(b.Steps) {
		return len(a.Steps) < len(b.Steps)
	}
	return a.ID < b.ID
}

func sortChains(chains []Chain) {
	sort.Slice(chains, func(i, j int) bool { return chains[i].ID < chains[j].ID })
}

func (s *State) chainWatermarks(c *Chain) map[string]event.Watermark {
	out := map[string]event.Watermark{}
	for _, st := range c.Steps {
		if w, ok := s.Watermarks[st.Issuer]; ok {
			out[st.Issuer] = w
		}
	}
	return out
}

// candidateChains enumerates every root-to-subject path for the resource.
func (s *State) candidateChains(res *Resource, subject string) []Chain {
	if subject == "" {
		return nil
	}
	// Index edges that target this resource+tenant+epoch and could end at the
	// subject. A path is any edge whose Subject is the subject, walked up via
	// Parent to a root.
	var tails []*Edge
	for _, e := range s.Edges {
		if e.Tenant == res.Tenant && e.Resource == res.ID && e.Epoch == res.Epoch && e.Subject == subject {
			tails = append(tails, e)
		}
	}
	sort.Slice(tails, func(i, j int) bool { return tails[i].ID < tails[j].ID })

	seen := map[string]bool{}
	var chains []Chain
	for _, tail := range tails {
		steps, ok := s.walk(tail)
		if !ok {
			continue
		}
		ch := Chain{ID: chainID(steps), Steps: steps}
		if seen[ch.ID] {
			continue
		}
		seen[ch.ID] = true
		chains = append(chains, ch)
	}
	return chains
}

// walk builds the ordered steps of a chain ending at tail. It refuses cycles and
// missing parents; the root must have an empty parent.
func (s *State) walk(tail *Edge) ([]ChainStep, bool) {
	var rev []*Edge
	cur := tail
	visited := map[string]bool{}
	for {
		if cur == nil || visited[cur.ID] {
			return nil, false
		}
		visited[cur.ID] = true
		rev = append(rev, cur)
		if cur.Parent == "" {
			break
		}
		cur = s.Edges[cur.Parent]
	}
	steps := make([]ChainStep, len(rev))
	for i := range rev {
		e := rev[len(rev)-1-i]
		steps[i] = ChainStep{
			EdgeID: e.ID, Parent: e.Parent, Issuer: e.Issuer, Gen: e.Gen,
			Actor: e.Actor, Subject: e.Subject,
			Scope: append([]string(nil), e.Scope...), Epoch: e.Epoch,
		}
	}
	return steps, true
}

func chainID(steps []ChainStep) string {
	ids := make([]string, len(steps))
	for i, st := range steps {
		ids[i] = st.EdgeID
	}
	return strings.Join(ids, ">")
}

// evaluateChain marks each step valid/invalid with reasons, and the chain as a
// whole valid only if every step is valid and scopes are nested.
func (s *State) evaluateChain(res *Resource, c *Chain) {
	c.Valid = true
	var chainReasons []string
	for i := range c.Steps {
		st := &c.Steps[i]
		reasons := s.edgeReasons(res, st, i == 0, parentScope(c.Steps, i))
		if len(reasons) > 0 {
			st.Valid = false
			st.Reasons = reasons
			c.Valid = false
			chainReasons = append(chainReasons, fmt.Sprintf("%s: %s", st.EdgeID, strings.Join(reasons, ",")))
		} else {
			st.Valid = true
		}
	}
	c.Reasons = chainReasons
	c.Usable = c.Valid
}

func parentScope(steps []ChainStep, i int) []string {
	if i == 0 {
		return nil
	}
	return steps[i-1].Scope
}

// edgeReasons returns every reason the step is not authorizable. An empty slice
// means the edge is valid in isolation (parent linkage checked by the walker,
// nesting here).
func (s *State) edgeReasons(res *Resource, st *ChainStep, isRoot bool, parentScope []string) []string {
	var reasons []string
	e := s.Edges[st.EdgeID]
	if e == nil {
		return []string{"missing edge"}
	}

	is := s.Issuers[e.Issuer]
	if is == nil {
		reasons = append(reasons, "unknown issuer "+e.Issuer)
	} else {
		if is.Quarantined {
			reasons = append(reasons, "issuer quarantined: "+is.QuarantineBy)
		}
		if is.CurrentGen != 0 && e.Gen != is.CurrentGen {
			reasons = append(reasons, fmt.Sprintf("stale credential generation g%d (current g%d)", e.Gen, is.CurrentGen))
		}
		gr := is.grant(e.Gen, e.Actor)
		if gr == nil {
			reasons = append(reasons, fmt.Sprintf("actor %s lacks authority at g%d", e.Actor, e.Gen))
		} else if isRoot && !gr.Admin {
			reasons = append(reasons, "root edge actor is not an admin")
		}
	}

	if isRoot {
		if e.Issuer != res.OwnerOrg {
			reasons = append(reasons, fmt.Sprintf("root issuer %s is not owner org %s", e.Issuer, res.OwnerOrg))
		}
	}

	if !isRoot {
		if !ScopeSubset(e.Scope, parentScope) {
			reasons = append(reasons, fmt.Sprintf("scope %s not within parent %s", joinScope(e.Scope), joinScope(parentScope)))
		}
	}

	if e.Epoch != res.Epoch {
		reasons = append(reasons, fmt.Sprintf("edge epoch %d != resource epoch %d", e.Epoch, res.Epoch))
	}

	if rv, ok := s.Revoked[e.ID]; ok {
		reasons = append(reasons, "revoked by "+rv.EvidenceID)
	}
	if dep, ok := s.Left[e.IssuerID()]; ok {
		reasons = append(reasons, "issuer "+e.IssuerID()+" left ("+dep.EvidenceID+")")
	}
	if dep, ok := s.Left[e.Subject]; ok {
		reasons = append(reasons, "subject "+e.Subject+" left ("+dep.EvidenceID+")")
	}

	if e.NotBefore != 0 && s.Now < e.NotBefore {
		reasons = append(reasons, fmt.Sprintf("not yet valid (now %d < %d)", s.Now, e.NotBefore))
	}
	if e.NotAfter != 0 && s.Now >= e.NotAfter {
		reasons = append(reasons, fmt.Sprintf("expired (now %d >= %d)", s.Now, e.NotAfter))
	}

	for _, b := range s.Bans {
		if s.banBlocks(b, e, res) {
			reasons = append(reasons, "emergency ban "+b.EvidenceID)
			break
		}
	}
	return reasons
}

// banBlocks reports whether an emergency ban covers this edge for the resource.
func (s *State) banBlocks(b Ban, e *Edge, res *Resource) bool {
	if b.Tenant != e.Tenant {
		return false
	}
	if b.Resource != "" && b.Resource != e.Resource {
		return false
	}
	if b.EdgeID != "" && b.EdgeID == e.ID {
		return true
	}
	if b.Subject != "" && (b.Subject == e.Subject || b.Subject == e.IssuerID()) {
		return true
	}
	// A ban with only a tenant+resource target blocks every edge on it.
	if b.EdgeID == "" && b.Subject == "" && b.Resource != "" {
		return true
	}
	return false
}

// applyClassPolicy adjusts Usable given the access class and the partition set.
func (s *State) applyClassPolicy(req Request, part map[string]bool, c *Chain) {
	if !c.Valid {
		c.Usable = false
		return
	}
	switch req.Class {
	case AccessLocal:
		// The owner's durable evidence is authoritative. We still require that
		// the choosing node actually holds each issuer's evidence at least up to
		// the edge's mint point: an edge we never durably accepted could hide a
		// revocation. Edges on the chain came from durable state, so this is a
		// self-check, recorded per step for auditability.
		for i := range c.Steps {
			st := &c.Steps[i]
			w, ok := s.Watermarks[st.Issuer]
			edge := s.Edges[st.EdgeID]
			if !ok || (edge != nil && w.Tick < edge.At) {
				st.Freshness = "evidence-not-durable"
				c.Usable = false
				c.Reasons = append(c.Reasons, fmt.Sprintf("LOCAL: no durable evidence up to mint for %s", st.EdgeID))
			} else {
				st.Freshness = "durable"
			}
		}
		c.Usable = c.Valid && c.Usable
	case AccessRemoteRead:
		// Cross-boundary chains are refused while the relevant issuer is
		// unreachable; all-reachable chains proceed unchanged.
		c.Usable = c.Valid
		for i := range c.Steps {
			st := &c.Steps[i]
			if part[st.Issuer] {
				st.Freshness = "unreachable"
				c.Usable = false
				c.Reasons = append(c.Reasons, fmt.Sprintf("REMOTE_READ: issuer %s unreachable, cannot refresh %s", st.Issuer, st.EdgeID))
			} else {
				st.Freshness = "fresh"
			}
		}
	case AccessRemoteWrite:
		// Fail closed on any unreachable issuer on the path; the owner-org
		// partition case was already short-circuited above.
		c.Usable = c.Valid
		for i := range c.Steps {
			st := &c.Steps[i]
			if part[st.Issuer] {
				st.Freshness = "unreachable"
				c.Usable = false
				c.Reasons = append(c.Reasons, fmt.Sprintf("REMOTE_WRITE: issuer %s unreachable", st.Issuer))
			} else {
				st.Freshness = "fresh"
			}
		}
	}
}

// appendEvidenceForTenant records all evidence relevant to the tenant.
func (s *State) appendEvidenceForTenant(d *Decision, req Request) {
	k := ResourceKey(req.Tenant, req.Resource)
	res := s.Resources[k]
	if res == nil {
		res = &Resource{Tenant: req.Tenant, ID: req.Resource}
	}
	d.EvidenceIDs = s.evidenceFor(res, nil)
	d.Watermarks = s.relevantWatermarks(res)
}

// appendEvidenceForChains records the evidence that could influence the
// decision: bans, revocations and departures touching the resource or the
// chains, plus rotations of their issuers.
func (s *State) appendEvidenceForChains(d *Decision, res *Resource, chains []Chain) {
	d.EvidenceIDs = s.evidenceFor(res, chains)
}

// relevantWatermarks returns the per-issuer watermarks of every issuer that
// appears on the resource's chains (or, absent chains, the resource owner).
func (s *State) relevantWatermarks(res *Resource) map[string]event.Watermark {
	out := map[string]event.Watermark{}
	if w, ok := s.Watermarks[res.OwnerOrg]; ok {
		out[res.OwnerOrg] = w
	}
	for _, e := range s.Edges {
		if e.Tenant == res.Tenant && e.Resource == res.ID {
			if w, ok := s.Watermarks[e.Issuer]; ok {
				out[e.Issuer] = w
			}
		}
	}
	return out
}

func (s *State) evidenceFor(res *Resource, chains []Chain) []string {
	ids := map[string]struct{}{}
	for _, b := range s.Bans {
		if b.Tenant == res.Tenant && (b.Resource == "" || b.Resource == res.ID) {
			ids[b.EvidenceID] = struct{}{}
		}
	}
	for _, c := range chains {
		for _, st := range c.Steps {
			if rv, ok := s.Revoked[st.EdgeID]; ok {
				ids[rv.EvidenceID] = struct{}{}
			}
			if dep, ok := s.Left[st.Issuer]; ok && dep.Subject == auth.Identity(st.Issuer, st.Actor) {
				ids[dep.EvidenceID] = struct{}{}
			}
			if dep, ok := s.Left[st.Subject]; ok {
				ids[dep.EvidenceID] = struct{}{}
			}
			if is := s.Issuers[st.Issuer]; is != nil && is.CurrentGen != st.Gen {
				for _, r := range s.Evidence {
					if r.Kind == event.KindRotate && r.Issuer == st.Issuer {
						ids[r.EvidenceID] = struct{}{}
					}
				}
			}
		}
	}
	for _, t := range s.Transfers[ResourceKey(res.Tenant, res.ID)] {
		ids[t.EvidenceID] = struct{}{}
	}
	out := make([]string, 0, len(ids))
	for id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}