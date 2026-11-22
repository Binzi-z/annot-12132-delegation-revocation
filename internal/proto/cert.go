// Package proto defines the admission certificate and its independent verifier,
// plus the small wire messages exchanged between the two local nodes.
//
// A certificate is self-contained: it carries the signed tenant/resource
// provenance, the signed grant and delegation event for every relevant edge,
// every evidence record the decision relied on, the node's per-issuer watermark
// attestations, and the node's verdict. Verify() consumes only the certificate
// and the public key registry; it never reads node state.
package proto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
	"ccrevoke/internal/model"
)

// Version is the certificate format version.
const Version = 1

// StepProof is one delegation edge together with the proof material that
// establishes its authority.
type StepProof struct {
	// Delegate is the issuer-signed delegation event. Its signature under
	// (Issuer, Gen) is the per-edge proof.
	Delegate event.Event `json:"delegate"`
	// Grant is the issuer-signed authority event proving Actor was entitled to
	// delegate at Gen at the time.
	Grant event.Event `json:"grant"`
	// Freshness is the node's classification of the step under the access
	// class: "durable", "fresh", or "unreachable".
	Freshness string `json:"freshness"`
}

// Certificate is a portable admission decision with all its supporting inputs.
type Certificate struct {
	Version int    `json:"version"`
	Node    string `json:"node"`

	Tenant   string            `json:"tenant"`
	Resource string            `json:"resource"`
	Subject  string            `json:"subject"`
	Action   string            `json:"action"`
	Class    model.AccessClass `json:"class"`

	// Resource provenance.
	TenantSource   event.Event   `json:"tenant_source"`
	ResourceSource event.Event   `json:"resource_source"`
	Transfers      []event.Event `json:"transfers,omitempty"`

	// Chain proofs. For an admitted decision Steps is exactly the chosen chain.
	// For a denied decision Steps lists every candidate edge so the evidence
	// horizon is auditable.
	ChainID    string                     `json:"chain_id,omitempty"`
	Steps      []StepProof                `json:"steps,omitempty"`
	Evidence   []event.EvidenceRecord     `json:"evidence,omitempty"`
	Watermarks map[string]event.Watermark `json:"watermarks,omitempty"`

	// Partition declaration used by the decision.
	Unreachable []string `json:"unreachable,omitempty"`

	// Verdict.
	Allowed   bool           `json:"allowed"`
	Reasons   []string       `json:"reasons,omitempty"`
	Now       int64          `json:"now"`
	IssuerGen map[string]int `json:"issuer_generations,omitempty"`

	// Attestation over the body.
	BodyHash string `json:"body_hash,omitempty"`
	Signature string `json:"signature,omitempty"`

	// Chains is an unsigned, human-audit view of every candidate path. It is
	// excluded from the signed body; verification never trusts it.
	Chains []model.Chain `json:"chains,omitempty"`
}

type certBody struct {
	Version        int                      `json:"version"`
	Node           string                   `json:"node"`
	Tenant         string                   `json:"tenant"`
	Resource       string                   `json:"resource"`
	Subject        string                   `json:"subject"`
	Action         string                   `json:"action"`
	Class          model.AccessClass        `json:"class"`
	TenantSource   event.Event              `json:"tenant_source"`
	ResourceSource event.Event              `json:"resource_source"`
	Transfers      []event.Event            `json:"transfers,omitempty"`
	ChainID        string                   `json:"chain_id,omitempty"`
	Steps          []StepProof              `json:"steps,omitempty"`
	Evidence       []event.EvidenceRecord   `json:"evidence,omitempty"`
	Watermarks     map[string]event.Watermark `json:"watermarks,omitempty"`
	Unreachable    []string                 `json:"unreachable,omitempty"`
	Allowed        bool                     `json:"allowed"`
	Reasons        []string                 `json:"reasons,omitempty"`
	Now            int64                    `json:"now"`
	IssuerGen      map[string]int           `json:"issuer_generations,omitempty"`
}

func (c *Certificate) body() certBody {
	return certBody{
		Version: c.Version, Node: c.Node, Tenant: c.Tenant, Resource: c.Resource,
		Subject: c.Subject, Action: c.Action, Class: c.Class,
		TenantSource: c.TenantSource, ResourceSource: c.ResourceSource,
		Transfers: c.Transfers, ChainID: c.ChainID, Steps: c.Steps,
		Evidence: c.Evidence, Watermarks: c.Watermarks, Unreachable: c.Unreachable,
		Allowed: c.Allowed, Reasons: c.Reasons, Now: c.Now, IssuerGen: c.IssuerGen,
	}
}

func (c *Certificate) bodyHash() string {
	raw, _ := json.Marshal(c.body())
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Sign computes the body hash and node signature.
func (c *Certificate) Sign(reg *auth.Registry) {
	c.BodyHash = c.bodyHash()
	c.Signature = reg.SignNode(c.Node, []byte(c.BodyHash))
}

// VerifyResult reports the outcome of independent verification.
type VerifyResult struct {
	OK     bool     `json:"ok"`
	Errors []string `json:"errors,omitempty"`
	// Recomputed is the decision the verifier derives from the certificate's
	// own signed inputs.
	Recomputed model.Decision `json:"recomputed"`
}

func (r *VerifyResult) errf(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
	r.OK = false
}

// Verify independently checks a certificate against the public registry. It
// returns OK only if every signature and hash checks out, the provenance
// reconstructs the resource, and re-folding the certificate's own signed inputs
// reproduces its verdict. For an admitted certificate it additionally enforces
// the chain shape, scope nesting, freshness, and watermark coverage.
func Verify(reg *auth.Registry, cert *Certificate) VerifyResult {
	res := VerifyResult{OK: true}
	if cert == nil {
		res.errf("nil certificate")
		return res
	}
	if cert.Version != Version {
		res.errf("unsupported certificate version %d", cert.Version)
		return res
	}
	if cert.BodyHash != cert.bodyHash() {
		res.errf("body hash mismatch")
	}
	if !reg.VerifyNode(cert.Node, []byte(cert.BodyHash), cert.Signature) {
		res.errf("node signature invalid")
	}

	// Provenance.
	if !checkEvent(reg, cert.TenantSource) {
		res.errf("tenant source: invalid event or signature")
	} else if cert.TenantSource.Kind != event.KindTenant || cert.TenantSource.Tenant != cert.Tenant {
		res.errf("tenant source does not describe tenant %q", cert.Tenant)
	}
	if !checkEvent(reg, cert.ResourceSource) {
		res.errf("resource source: invalid event or signature")
	} else if cert.ResourceSource.Kind != event.KindResource || cert.ResourceSource.Tenant != cert.Tenant || cert.ResourceSource.Resource != cert.Resource {
		res.errf("resource source does not describe resource %q/%q", cert.Tenant, cert.Resource)
	}
	for i, tr := range cert.Transfers {
		if !checkEvent(reg, tr) || tr.Kind != event.KindTransfer {
			res.errf("transfer %d: invalid transfer event", i)
		}
	}

	// Rebuild the state purely from the certificate's signed inputs.
	evs := []event.Event{cert.TenantSource, cert.ResourceSource}
	evs = append(evs, cert.Transfers...)
	seenEdge := map[string]bool{}
	for _, st := range cert.Steps {
		if !checkEvent(reg, st.Delegate) {
			res.errf("edge %s: delegation signature invalid", st.Delegate.EdgeID)
		} else if st.Delegate.Kind != event.KindDelegate {
			res.errf("edge %s: not a delegation event", st.Delegate.EdgeID)
		}
		if !checkEvent(reg, st.Grant) {
			res.errf("edge %s: grant signature invalid", st.Delegate.EdgeID)
		} else if st.Grant.Kind != event.KindAuthority {
			res.errf("edge %s: grant is not an authority event", st.Delegate.EdgeID)
		}
		if !seenEdge[st.Delegate.EdgeID] {
			seenEdge[st.Delegate.EdgeID] = true
			evs = append(evs, st.Grant, st.Delegate)
		}
	}
	var evidenceEvents []event.Event
	for _, r := range cert.Evidence {
		if r.Event.Kind == "" {
			res.errf("evidence %s: missing embedded event", r.EvidenceID)
			continue
		}
		if !checkEvent(reg, r.Event) {
			res.errf("evidence %s: signature invalid", r.EvidenceID)
		}
		evidenceEvents = append(evidenceEvents, r.Event)
	}
	evs = append(evs, evidenceEvents...)

	event.CanonicalOrder(evs)
	state, err := model.Fold(evs)
	if err != nil {
		res.errf("fold: %v", err)
		return res
	}
	state.ApplyEvidence(cert.Evidence)
	state.MergeWatermarks(cert.Watermarks)
	// The node attests its decision time. Expiry/not-before are evaluated
	// against it; because it is inside the signed body, a verifier reproduces
	// the exact same time-dependent verdict.
	if cert.Now > state.Now {
		state.Now = cert.Now
	}

	// Recomputed decision from signed inputs.
	req := model.Request{
		Tenant: cert.Tenant, Resource: cert.Resource, Subject: cert.Subject,
		Action: cert.Action, Class: cert.Class, NodeOrg: cert.Node,
		Unreachable: cert.Unreachable,
	}
	recomputed := state.Evaluate(req)
	res.Recomputed = recomputed

	if recomputed.Allowed != cert.Allowed {
		res.errf("verdict mismatch: certificate says allowed=%v, recomputation says %v", cert.Allowed, recomputed.Allowed)
	}
	if cert.Allowed {
		if cert.ChainID == "" {
			res.errf("allowed certificate has no chain")
		} else if recomputed.ChainID != "" && cert.ChainID != recomputed.ChainID {
			res.errf("chain mismatch: certificate %q, recomputation %q", cert.ChainID, recomputed.ChainID)
		}
		// An admitted certificate must carry exactly its chosen chain.
		if err := checkChainShape(cert); err != nil {
			res.errf("%v", err)
		}
		for _, st := range cert.Steps {
			if st.Freshness == "" {
				res.errf("edge %s: missing freshness proof", st.Delegate.EdgeID)
			}
			if st.Freshness == "unreachable" {
				res.errf("edge %s: unreachable in an admitted certificate", st.Delegate.EdgeID)
			}
			w, ok := cert.Watermarks[st.Delegate.Issuer]
			if !ok {
				res.errf("edge %s: no watermark attestation for issuer %s", st.Delegate.EdgeID, st.Delegate.Issuer)
				continue
			}
			if w.Tick < st.Delegate.Tick || (w.Gen > 0 && st.Delegate.Gen > w.Gen) {
				res.errf("edge %s: watermark does not cover mint (tick %d, gen %d)", st.Delegate.EdgeID, st.Delegate.Tick, st.Delegate.Gen)
			}
		}
	}
	return res
}

func checkEvent(reg *auth.Registry, e event.Event) bool {
	if e.Kind == "" || e.Hash == "" || e.Sig == "" {
		return false
	}
	return e.VerifyHash() && e.VerifySig(reg)
}

// checkChainShape enforces the root-to-subject structure of an admitted chain.
func checkChainShape(cert *Certificate) error {
	if len(cert.Steps) == 0 {
		return fmt.Errorf("allowed certificate has no step proofs")
	}
	var prevScope []string
	for i, st := range cert.Steps {
		e := st.Delegate
		if i == 0 {
			if e.Parent != "" {
				return fmt.Errorf("root step has a parent")
			}
			if !st.Grant.Admin {
				return fmt.Errorf("root step: grant is not admin")
			}
		} else {
			if e.Parent != cert.Steps[i-1].Delegate.EdgeID {
				return fmt.Errorf("step %d: parent %q does not match previous edge %q", i, e.Parent, cert.Steps[i-1].Delegate.EdgeID)
			}
			if auth.Identity(e.Issuer, e.Actor) != cert.Steps[i-1].Delegate.Subject {
				return fmt.Errorf("step %d: actor %q is not previous subject %q", i, auth.Identity(e.Issuer, e.Actor), cert.Steps[i-1].Delegate.Subject)
			}
			if !model.ScopeSubset(e.Scope, prevScope) {
				return fmt.Errorf("step %d: scope not nested", i)
			}
		}
		if st.Grant.Issuer != e.Issuer || st.Grant.Gen != e.Gen || st.Grant.Actor != e.Actor {
			return fmt.Errorf("step %d: grant does not match edge issuer/gen/actor", i)
		}
		prevScope = e.Scope
	}
	if last := cert.Steps[len(cert.Steps)-1].Delegate; last.Subject != cert.Subject {
		return fmt.Errorf("last step subject %q is not requester %q", last.Subject, cert.Subject)
	}
	return nil
}

// FromDecision assembles a certificate from a node's decision and state.
// It is the node-side constructor; verification never needs node state.
func FromDecision(st *model.State, d model.Decision, req model.Request, nodeOrg string, reg *auth.Registry) *Certificate {
	cert := &Certificate{
		Version: Version, Node: nodeOrg,
		Tenant: d.Tenant, Resource: d.Resource, Subject: d.Subject,
		Action: d.Action, Class: d.Class, Allowed: d.Allowed,
		Reasons: append([]string(nil), d.Reasons...), Now: d.Now,
		Unreachable: append([]string(nil), req.Unreachable...),
		IssuerGen:   map[string]int{},
		Chains:      d.Chains,
	}

	if t := st.Tenants[d.Tenant]; t != nil {
		cert.TenantSource = t.Source
	}
	k := model.ResourceKey(d.Tenant, d.Resource)
	if r := st.Resources[k]; r != nil {
		cert.ResourceSource = r.Source
		for _, tr := range st.Transfers[k] {
			if rec, ok := st.Evidence[tr.EvidenceID]; ok {
				cert.Transfers = append(cert.Transfers, rec.Event)
			}
		}
	}

	if d.Allowed && d.ChainID != "" {
		for i := range d.Chains {
			if d.Chains[i].ID != d.ChainID {
				continue
			}
			cert.ChainID = d.ChainID
			for _, step := range d.Chains[i].Steps {
				sp, ok := stepProof(st, step)
				if !ok {
					continue
				}
				cert.Steps = append(cert.Steps, sp)
				cert.IssuerGen[step.Issuer] = step.Gen
			}
			break
		}
	} else {
		// Denied: include every candidate edge that has a fully resolvable
		// proof (delegate + grant), deduplicated, so the evidence horizon behind
		// each failure is independently checkable. Edges lacking a grant are
		// not provable and are omitted; omitting them cannot flip a deny to an
		// allow because such edges were never authorizable.
		seen := map[string]bool{}
		for _, ch := range d.Chains {
			for _, step := range ch.Steps {
				if seen[step.EdgeID] {
					continue
				}
				seen[step.EdgeID] = true
				sp, ok := stepProof(st, step)
				if !ok {
					continue
				}
				cert.Steps = append(cert.Steps, sp)
				cert.IssuerGen[step.Issuer] = step.Gen
			}
		}
	}

	// Evidence: every decision-relevant evidence record.
	seen := map[string]bool{}
	addEvidence := func(id string) {
		if id == "" || seen[id] {
			return
		}
		if rec, ok := st.Evidence[id]; ok {
			cert.Evidence = append(cert.Evidence, rec)
			seen[id] = true
		}
	}
	for _, id := range d.EvidenceIDs {
		addEvidence(id)
	}
	sort.Slice(cert.Evidence, func(i, j int) bool { return cert.Evidence[i].EvidenceID < cert.Evidence[j].EvidenceID })

	cert.Watermarks = map[string]event.Watermark{}
	owner := d.ResourceOwner
	if owner == "" && cert.ResourceSource.OwnerOrg != "" {
		owner = cert.ResourceSource.OwnerOrg
	}
	if w, ok := st.Watermarks[owner]; ok {
		cert.Watermarks[owner] = w
	}
	for issuer := range cert.IssuerGen {
		if w, ok := st.Watermarks[issuer]; ok {
			cert.Watermarks[issuer] = w
		}
	}
	cert.Sign(reg)
	return cert
}

func stepProof(st *model.State, step model.ChainStep) (StepProof, bool) {
	out := StepProof{Freshness: step.Freshness}
	e := st.Edges[step.EdgeID]
	if e == nil {
		return out, false
	}
	out.Delegate = e.Source
	is := st.Issuers[step.Issuer]
	if is == nil {
		return out, false
	}
	gr := is.Grant(step.Gen, step.Actor)
	if gr == nil {
		return out, false
	}
	out.Grant = gr.Source
	return out, true
}