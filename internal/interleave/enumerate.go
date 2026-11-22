package interleave

import (
	"fmt"
	"strings"

	"ccrevoke/internal/model"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/scenario"
)

// Bob and Carl are the two independent-path subjects in the reference world.
func BobID() string  { return scenario.Id(scenario.OrgB, scenario.Bob) }
func CarlID() string { return scenario.Id(scenario.OrgB, scenario.Carl) }

// CheckTransitions compares the invariant-relevant observations around one
// action and returns violations.
func CheckTransitions(before, after Observation, path string) []Violation {
	var vs []Violation
	// Ban monotonicity is about distinct ban claims, not raw record count: a
	// second ban on the same target is a duplicate claim collapsed by the
	// minimal-evidence rule.
	if missing := missingEvidence(before.BanClaims, after.BanClaims); len(missing) > 0 {
		vs = append(vs, Violation{InvBanMonotone, path,
			"ban claims disappeared: " + strings.Join(missing, ",")})
	}
	if missing := missingEvidence(before.RevokeClaims, after.RevokeClaims); len(missing) > 0 {
		vs = append(vs, Violation{InvRevokedStaysDead, path,
			"revocation claims disappeared: " + strings.Join(missing, ",")})
	}
	if missing := missingEvidence(before.Claims, after.Claims); len(missing) > 0 {
		vs = append(vs, Violation{InvBanMonotone, path,
			"evidence claims disappeared: " + strings.Join(missing, ",")})
	}
	if after.RevokedCount < before.RevokedCount {
		vs = append(vs, Violation{InvRevokedStaysDead, path,
			fmt.Sprintf("revocation count dropped %d -> %d", before.RevokedCount, after.RevokedCount)})
	}
	return vs
}

func missingEvidence(before, after []string) []string {
	set := map[string]bool{}
	for _, id := range after {
		set[id] = true
	}
	var out []string
	for _, id := range before {
		if !set[id] {
			out = append(out, id)
		}
	}
	return out
}

// History tracks which actions have occurred so far, enabling order-sensitive
// scenario assertions.
type History struct {
	Kinds      []ActionKind
	Labels     []string
	RevokedBob bool // chain1 child edge revoked
	RevokedCarl bool // chain2 child edge revoked
	Rotated    bool
	Reauth     bool
	Banned     bool
	Transferred bool
	ErinExpired bool // expiring third chain was minted and has expired
}

func (h History) String() string { return strings.Join(h.Labels, " |> ") }

// Advance returns a copy of the history updated with an action.
func (h History) Advance(act Action) History {
	n := History{
		Kinds:       append(append([]ActionKind(nil), h.Kinds...), act.Kind),
		Labels:      append(append([]string(nil), h.Labels...), string(act.Kind)+":"+act.Label),
		RevokedBob:  h.RevokedBob, RevokedCarl: h.RevokedCarl,
		Rotated: h.Rotated, Reauth: h.Reauth, Banned: h.Banned, Transferred: h.Transferred,
		ErinExpired: h.ErinExpired,
	}
	switch act.Label {
	case "revoke chain1 child edge (dave->bob)":
		n.RevokedBob = true
	case "revoke chain2 child edge (olga->carl)":
		n.RevokedCarl = true
	case "rotate orgA to next generation (invalidates prior-gen edges)":
		n.Rotated = true
		// A rotation invalidates every prior-generation edge, so a prior reauth
		// no longer rescues the old chain.
		n.Reauth = false
	case "reauthorize chain2 at the current generation":
		n.Reauth = true
	case "transfer doc-a to orgB (epoch 2)":
		n.Transferred = true
	case "emergency-ban bob on doc-a":
		n.Banned = true
	case "mint then expire an erin chain (ops->erin)":
		n.ErinExpired = true
	}
	return n
}

// Assert checks the named scenario invariants for the observation after an
// action, given the full history. It returns the first violation.
func Assert(obs Observation, h History, m *Machine) []Violation {
	var vs []Violation
	path := h.String()

	// Ban monotonicity: a resource-wide ban on bob must deny bob, forever.
	if h.Banned {
		if d := m.Evaluate(BobID(), "read"); d.Allowed {
			vs = append(vs, Violation{InvBanMonotone, path, "banned subject bob was allowed"})
		}
	}

	// Transfer/rotation kill old chains. Until a reauthorization follows, both
	// subject paths rooted in the old generation/epoch must be denied.
	oldChainsDead := (h.Rotated || h.Transferred) && !h.Reauth
	if oldChainsDead {
		if !h.Banned {
			if d := m.Evaluate(BobID(), "read"); d.Allowed {
				vs = append(vs, Violation{InvRevokedStaysDead, path,
					"bob usable through stale generation/epoch"})
			}
		}
		if d := m.Evaluate(CarlID(), "read"); d.Allowed {
			vs = append(vs, Violation{InvRevokedStaysDead, path,
				"carl usable through stale generation/epoch"})
		}
	}

	// Revocation isolation: revoking chain1 must never disable chain2 (carl),
	// unless chain2 was itself revoked or another adverse action killed it.
	if h.RevokedBob && !h.RevokedCarl && !h.Rotated && !h.Transferred && !h.Banned {
		if d := m.Evaluate(CarlID(), "read"); !d.Allowed {
			vs = append(vs, Violation{InvIndependentPath, path,
				"revoking chain1 disabled independent chain2 (carl)"})
		}
	}
	if h.RevokedCarl && !h.RevokedBob && !h.Rotated && !h.Transferred && !h.Banned {
		if d := m.Evaluate(BobID(), "read"); !d.Allowed {
			vs = append(vs, Violation{InvIndependentPath, path,
				"revoking chain2 disabled independent chain1 (bob)"})
		}
	}

	// Expiry: an expiring chain must be usable before its deadline and unusable
	// after, without disturbing the two permanent chains.
	if h.ErinExpired {
		if obs.ErinAllowed {
			vs = append(vs, Violation{InvExpiryHonored, path,
				"expired chain for erin still usable"})
		}
	}

	// Non-revoked stays live: with no adverse action at all, both subjects must
	// remain allowed.
	if !h.RevokedBob && !h.RevokedCarl && !h.Rotated && !h.Transferred && !h.Banned {
		if d := m.Evaluate(BobID(), "read"); !d.Allowed {
			vs = append(vs, Violation{InvNonRevokedStaysLive, path, "bob denied without cause"})
		}
		if d := m.Evaluate(CarlID(), "read"); !d.Allowed {
			vs = append(vs, Violation{InvNonRevokedStaysLive, path, "carl denied without cause"})
		}
	}

	// Every decision must carry a verifiable certificate.
	for _, subj := range []string{BobID(), CarlID()} {
		if err := m.VerifyCert(subj, "read"); err != nil {
			vs = append(vs, Violation{InvCertificateVerify, path, err.Error()})
		}
	}
	return vs
}

// VerifyCert builds and independently verifies a certificate for a decision.
func (m *Machine) VerifyCert(subject, action string) error {
	req := model.Request{
		Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subject,
		Action: action, Class: model.AccessLocal, NodeOrg: scenario.OrgA,
	}
	d := m.State.Evaluate(req)
	cert := proto.FromDecision(m.State, d, req, scenario.OrgA, m.Reg)
	res := proto.Verify(m.Reg, cert)
	if !res.OK {
		return fmt.Errorf("certificate for %s did not verify: %v", subject, res.Errors)
	}
	return nil
}

// Enumerate walks every action sequence up to depth, applying the transition
// checks and the scenario assertions. It returns the first violation, or nil.
func Enumerate(depth int) (*Violation, int) {
	root := New()
	states := 0

	var walk func(m *Machine, h History, remaining int) *Violation
	walk = func(m *Machine, h History, remaining int) *Violation {
		states++
		obs := m.Observe()
		for _, v := range Assert(obs, h, m) {
			return &v
		}
		if remaining == 0 {
			return nil
		}
		for _, act := range Actions(m) {
			if len(h.Kinds) == 0 {
				// Reauthorization presupposes a prior rotation; exclude it from
				// the root alphabet so the world stays coherent.
				if act.Kind == ActReauthorize {
					continue
				}
			} else if !containsKind(allowedAfter(h.Kinds[len(h.Kinds)-1]), act.Kind) {
				continue
			}
			next := m.Clone()
			act.Apply(next)
			nextObs := next.Observe()
			nextH := h.Advance(act)
			if vs := CheckTransitions(obs, nextObs, nextH.String()); len(vs) > 0 {
				return &vs[0]
			}
			if v := walk(next, nextH, remaining-1); v != nil {
				return v
			}
		}
		return nil
	}
	return walk(root, History{}, depth), states
}

func containsKind(list []ActionKind, k ActionKind) bool {
	for _, x := range list {
		if x == k {
			return true
		}
	}
	return false
}