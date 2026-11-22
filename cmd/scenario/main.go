// Command scenario runs the reference state-machine interleaving enumeration and
// a two-real-process replay, printing the per-decision admission certificates so
// every verdict is checkable.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"ccrevoke/internal/auth"
	"ccrevoke/internal/event"
	"ccrevoke/internal/interleave"
	"ccrevoke/internal/model"
	"ccrevoke/internal/node"
	"ccrevoke/internal/proto"
	"ccrevoke/internal/replay"
	"ccrevoke/internal/scenario"
)

// stdout is the transcript destination; tests may swap it for a buffer.
var stdout io.Writer = os.Stdout

// transcriptWriter collects output for tests.
type transcriptWriter struct{ buf []byte }

func (w *transcriptWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}
func (w *transcriptWriter) String() string { return string(w.buf) }

func out(format string, args ...any) { fmt.Fprintf(stdout, format, args...) }

func main() {
	var (
		depth   = flag.Int("depth", 4, "max action-sequence depth to enumerate")
		doProc  = flag.Bool("process", true, "also run the two-real-process replay")
		keep    = flag.Bool("keep", false, "keep the replay's runtime directory")
		verbose = flag.Bool("v", false, "print every invariant checked")
	)
	flag.Parse()

	out("== reference state-machine interleavings ==\n")
	v, states := interleave.Enumerate(*depth)
	if v != nil {
		out("VIOLATION after %d states: %v\n", states, *v)
		os.Exit(1)
	}
	out("explored %d reachable states up to depth %d: all invariants held\n", states, *depth)
	if *verbose {
		for _, inv := range []string{
			interleave.InvIndependentPath, interleave.InvRevokedStaysDead,
			interleave.InvBanMonotone, interleave.InvNonRevokedStaysLive,
			interleave.InvExpiryHonored, interleave.InvCertificateVerify,
		} {
			out("  checked: %s\n", inv)
		}
	}

	if !*doProc {
		return
	}
	out("\n== two-real-process replay (controllable queue) ==\n")
	if err := runProcessReplay(*keep); err != nil {
		out("REPLAY FAILED: %v\n", err)
		os.Exit(1)
	}
}

func runProcessReplay(keep bool) error {
	w, err := replay.StartWorld(scenario.Seed, 1)
	if err != nil {
		return err
	}
	defer w.Close(keep)
	if err := w.Sync(0); err != nil {
		return err
	}
	reg := scenario.NewFixture().Reg

	bob := scenario.Id(scenario.OrgB, scenario.Bob)
	carl := scenario.Id(scenario.OrgB, scenario.Carl)
	read := func(org, subject string) model.Request {
		class := model.AccessRemoteRead
		if org == scenario.OrgA {
			class = model.AccessLocal
		}
		return model.Request{
			Tenant: scenario.TenantA, Resource: scenario.ResA, Subject: subject,
			Action: "read", Class: class, NodeOrg: org,
		}
	}
	report := func(label string, d model.Decision, cert *proto.Certificate) error {
		out("-- %s: %s --\n%s", label, verdict(d.Allowed), d.Explain())
		if cert != nil {
			raw, _ := json.MarshalIndent(cert, "  ", "  ")
			out("  certificate: %s\n", raw)
			if res := proto.Verify(reg, cert); !res.OK {
				return fmt.Errorf("certificate did not verify: %v", res.Errors)
			}
			out("  certificate: independently VERIFIED\n")
		}
		return nil
	}

	dBob, cBob, err := w.B.Client().Evaluate(read(scenario.OrgB, bob))
	if err != nil {
		return err
	}
	if err := report("baseline bob", dBob, cBob); err != nil {
		return err
	}
	dCarl, cCarl, err := w.B.Client().Evaluate(read(scenario.OrgB, carl))
	if err != nil {
		return err
	}
	if err := report("baseline carl", dCarl, cCarl); err != nil {
		return err
	}
	if !dBob.Allowed || !dCarl.Allowed {
		return fmt.Errorf("baseline should admit both independent paths")
	}

	if _, err := w.A.Client().Author(node.AuthorInput{
		Kind: event.KindRevoke, Issuer: scenario.OrgA, Gen: 1, Actor: scenario.AdminA,
		EdgeID: scenario.EdgeADevBob, EvidenceID: "rev-scenario",
	}); err != nil {
		return err
	}
	if err := w.Sync(0); err != nil {
		return err
	}
	dBob2, cBob2, err := w.B.Client().Evaluate(read(scenario.OrgB, bob))
	if err != nil {
		return err
	}
	if err := report("after revoke bob", dBob2, cBob2); err != nil {
		return err
	}
	if dBob2.Allowed {
		return fmt.Errorf("bob must be denied after revocation")
	}
	dCarl2, cCarl2, err := w.B.Client().Evaluate(read(scenario.OrgB, carl))
	if err != nil {
		return err
	}
	if err := report("after revoke carl", dCarl2, cCarl2); err != nil {
		return err
	}
	if !dCarl2.Allowed {
		return fmt.Errorf("carl's independent chain must survive the revocation")
	}

	if err := w.B.Client().Checkpoint(); err != nil {
		return err
	}
	if err := w.B.Restart(scenario.Seed, 1); err != nil {
		return err
	}
	dBob3, cBob3, err := w.B.Client().Evaluate(read(scenario.OrgB, bob))
	if err != nil {
		return err
	}
	if err := report("after compaction+restart bob", dBob3, cBob3); err != nil {
		return err
	}
	if dBob3.Allowed {
		return fmt.Errorf("revocation lost across compaction+restart")
	}

	out("\nall two-process checks passed\n")
	return nil
}

func verdict(allowed bool) string {
	if allowed {
		return "ALLOW"
	}
	return "DENY"
}

var _ = auth.NewRegistry