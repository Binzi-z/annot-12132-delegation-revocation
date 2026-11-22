package interleave

import (
	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
	"ccrevoke/internal/scenario"
)

// fmtGen builds a generation-scoped edge id, e.g. prefix="g", gen=2, suffix="-x"
// yields "g2-x".
func fmtGen(prefix string, gen int, suffix string) string {
	return prefix + itoa(gen) + suffix
}

// author appends a signed event from orgA, continuing orgA's hash chain within
// this machine's log. It is the single event-authoring primitive for actions.
func (m *Machine) author(in event.Event) event.Event {
	var seq uint64
	var prev string
	for _, e := range m.Log {
		if e.Node == scenario.OrgA {
			seq = e.Seq
			prev = e.Hash
		}
	}
	e := in
	e.Node = scenario.OrgA
	e.Seq = seq + 1
	e.Prev = prev
	e.Tick = m.Now + 1
	if e.Issuer == "" {
		e.Issuer = scenario.OrgA
	}
	if e.EvidenceID == "" && event.IsEvidenceKind(e.Kind) {
		e.EvidenceID = string(e.Kind) + "-" + scenario.OrgA + "-" + itoa(int(e.Seq))
	}
	e.Sign(m.Reg)
	m.Append(e)
	return e
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Actions returns the action alphabet, each a pure transition over a clone.
func Actions(m *Machine) []Action {
	subj := func(org, name string) string { return auth.Identity(org, name) }
	return []Action{
		{
			Kind: ActRevokeEdge, Label: "revoke chain1 child edge (dave->bob)",
			Apply: func(mm *Machine) {
				mm.author(event.Event{Kind: event.KindRevoke, Gen: 1, Actor: scenario.AdminA, EdgeID: scenario.EdgeADevBob})
			},
		},
		{
			Kind: ActRevokeEdge, Label: "revoke chain2 child edge (olga->carl)",
			Apply: func(mm *Machine) {
				mm.author(event.Event{Kind: event.KindRevoke, Gen: 1, Actor: scenario.AdminA, EdgeID: scenario.EdgeAOpsCarl})
			},
		},
		{
			Kind: ActRotate, Label: "rotate orgA to next generation (invalidates prior-gen edges)",
			Apply: func(mm *Machine) {
				cur := 1
				if is := mm.State.Issuer(scenario.OrgA); is != nil && is.CurrentGen > 0 {
					cur = is.CurrentGen
				}
				next := cur + 1
				mm.author(event.Event{Kind: event.KindRotate, Gen: next, FromGen: cur, ToGen: next})
				mm.author(event.Event{Kind: event.KindAuthority, Gen: next, Actor: scenario.AdminA, Admin: true})
			},
		},
		{
			Kind: ActReauthorize, Label: "reauthorize chain2 at the current generation",
			Apply: func(mm *Machine) {
				gen := 1
				if is := mm.State.Issuer(scenario.OrgA); is != nil && is.CurrentGen > 0 {
					gen = is.CurrentGen
				}
				mm.author(event.Event{Kind: event.KindAuthority, Gen: gen, Actor: scenario.OpsA})
				mm.author(event.Event{Kind: event.KindDelegate, Gen: gen, Actor: scenario.AdminA, EdgeID: fmtGen("g", gen, "-admin-ops"), Subject: subj(scenario.OrgA, scenario.OpsA), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read", "write"}})
				mm.author(event.Event{Kind: event.KindDelegate, Gen: gen, Actor: scenario.OpsA, EdgeID: fmtGen("g", gen, "-ops-carl"), Parent: fmtGen("g", gen, "-admin-ops"), Subject: subj(scenario.OrgB, scenario.Carl), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read"}})
			},
		},
		{
			Kind: ActTransfer, Label: "transfer doc-a to orgB (epoch 2)",
			Apply: func(mm *Machine) {
				mm.author(event.Event{Kind: event.KindTransfer, Gen: 1, Actor: scenario.AdminA, Tenant: scenario.TenantA, Resource: scenario.ResA, ToOrg: scenario.OrgB, Epoch: 2})
			},
		},
		{
			Kind: ActExpire, Label: "mint then expire an erin chain (ops->erin)",
			Apply: func(mm *Machine) {
				// A third, independent, expiring chain rooted at the same admin
				// edge as carl's. NotAfter is two ticks ahead; three clock ticks
				// then push logical time past it.
				mm.author(event.Event{Kind: event.KindDelegate, Gen: 1, Actor: scenario.OpsA, EdgeID: scenario.EdgeAOpsErin, Parent: scenario.EdgeAAdminOps, Subject: subj(scenario.OrgB, scenario.Erin), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read"}, NotAfter: mm.Now + 2})
				mm.author(event.Event{Kind: event.KindClock})
				mm.author(event.Event{Kind: event.KindClock})
				mm.author(event.Event{Kind: event.KindClock})
			},
		},
		{
			Kind: ActBan, Label: "emergency-ban bob on doc-a",
			Apply: func(mm *Machine) {
				mm.author(event.Event{Kind: event.KindBan, Gen: 1, Actor: scenario.AdminA, Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subj(scenario.OrgB, scenario.Bob), Reason: "emergency"})
			},
		},
		{
			Kind: ActCompact, Label: "compact (snapshot + retain evidence)",
			Apply: func(mm *Machine) { mm.Compact() },
		},
		{
			Kind: ActRestart, Label: "restart (recover from snapshot + evidence)",
			Apply: func(mm *Machine) { mm.Restart() },
		},
		{
			Kind: ActSwitchPath, Label: "switch path: revoke one of two independent chains",
			Apply: func(mm *Machine) {
				// Add a second independent chain to bob via olga/carl? Instead,
				// demonstrate a path switch with no semantic change: revoke the
				// short-lived extra edge while the primary chain remains.
				mm.author(event.Event{Kind: event.KindDelegate, Gen: 1, Actor: scenario.AdminA, EdgeID: "alt-bob", Subject: subj(scenario.OrgB, scenario.Bob), Tenant: scenario.TenantA, Resource: scenario.ResA, Epoch: 1, Scope: []string{"read"}})
				mm.author(event.Event{Kind: event.KindRevoke, Gen: 1, Actor: scenario.AdminA, EdgeID: "alt-bob"})
			},
		},
	}
}

// allowedPairs lists actions that may meaningfully follow one another; used to
// keep the enumeration small and focused on the interesting interleavings.
func allowedAfter(k ActionKind) []ActionKind {
	switch k {
	case ActRevokeEdge:
		return []ActionKind{ActRevokeEdge, ActRotate, ActTransfer, ActBan, ActCompact, ActRestart}
	case ActRotate:
		return []ActionKind{ActReauthorize, ActCompact, ActRestart, ActBan, ActRotate}
	case ActReauthorize:
		return []ActionKind{ActCompact, ActRestart, ActBan, ActRevokeEdge, ActTransfer}
	case ActTransfer:
		return []ActionKind{ActCompact, ActRestart, ActBan}
	case ActExpire:
		return []ActionKind{ActCompact, ActRestart, ActBan, ActExpire}
	case ActBan:
		return []ActionKind{ActCompact, ActRestart, ActBan, ActRevokeEdge}
	case ActCompact:
		return []ActionKind{ActRestart, ActRevokeEdge, ActBan, ActSwitchPath, ActRotate}
	case ActRestart:
		return []ActionKind{ActCompact, ActRevokeEdge, ActBan, ActSwitchPath, ActRotate, ActTransfer}
	case ActSwitchPath:
		return []ActionKind{ActCompact, ActRestart, ActBan, ActRevokeEdge}
	}
	return nil
}