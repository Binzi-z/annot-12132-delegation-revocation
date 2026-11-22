package replay

import (
	"fmt"
	"os"
	"path/filepath"

	"ccrevoke/internal/event"
)

// World is a pair of real node processes plus a controllable queue between them.
// All replication in every scenario goes through the queue, so partitions,
// drops and restarts are explicit and reproducible.
type World struct {
	A      *Process
	B      *Process
	Queue  *Queue
	seed   string
	qdir   string
}

// StartWorld launches two real processes and returns them wired to a fresh
// queue. Caller must Close.
func StartWorld(seed string, tickStep int64) (*World, error) {
	base, err := os.MkdirTemp("", "ccrevoke-world-")
	if err != nil {
		return nil, err
	}
	a, err := Start("orgA", filepath.Join(base, "A"), seed, tickStep, "world", nil)
	if err != nil {
		os.RemoveAll(base)
		return nil, err
	}
	b, err := Start("orgB", filepath.Join(base, "B"), seed, tickStep, "none", nil)
	if err != nil {
		a.Stop()
		os.RemoveAll(base)
		return nil, err
	}
	return &World{A: a, B: b, Queue: NewQueue(), seed: seed, qdir: base}, nil
}

// Dir returns the world's root directory.
func (w *World) Dir() string { return w.qdir }

// Close stops both processes and removes temp state (unless Keep).
func (w *World) Close(keep bool) {
	_ = w.A.Stop()
	_ = w.B.Stop()
	if !keep {
		_ = os.RemoveAll(w.qdir)
	}
}

// ClientFor returns the client for an org.
func (w *World) ClientFor(org string) *Client {
	if org == w.A.Org {
		return w.A.Client()
	}
	return w.B.Client()
}

// ProcessFor returns the process for an org.
func (w *World) ProcessFor(org string) *Process {
	if org == w.A.Org {
		return w.A
	}
	return w.B
}

// Pull stages every event and piece of evidence that `from` holds and `to`
// has not yet accepted, into the queue. It is the "offer" half of replication.
func (w *World) Pull(from, to string) error {
	src := w.ClientFor(from)
	dst := w.ClientFor(to)

	// Events authored by `from`, in sequence order.
	evs, err := src.Events(from, 0)
	if err != nil {
		return err
	}
	have := map[uint64]bool{}
	if batch, err := dst.Events(from, 0); err == nil {
		for _, e := range batch {
			have[e.Seq] = true
		}
	}
	for _, e := range evs {
		if !have[e.Seq] {
			w.Queue.Push(Message{From: from, To: to, Kind: "event", Event: e})
		}
	}

	// Evidence (so bans propagate even if the event stream is delayed).
	// Evidence events are also in the event stream; merging is idempotent and
	// additionally covers evidence retained from before a peer's compaction.
	recs, err := src.Evidence()
	if err != nil {
		return err
	}
	dstEv, err := dst.Evidence()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, r := range dstEv {
		seen[r.EvidenceID] = true
	}
	var fresh []event.EvidenceRecord
	for _, r := range recs {
		if !seen[r.EvidenceID] {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) > 0 {
		w.Queue.Push(Message{From: from, To: to, Kind: "evidence", Evidence: fresh})
	}
	return nil
}

// PullBoth stages both directions.
func (w *World) PullBoth() error {
	if err := w.Pull(w.A.Org, w.B.Org); err != nil {
		return err
	}
	return w.Pull(w.B.Org, w.A.Org)
}

// Deliver flushes every deliverable queued message. dup duplicates each
// message `dup` extra times.
func (w *World) Deliver(dup int) error {
	return w.Queue.Deliver(func(m Message) error {
		dst := w.ClientFor(m.To)
		switch m.Kind {
		case "evidence":
			return dst.MergeEvidence(m.Evidence)
		default:
			if err := dst.Ingest(m.Event); err != nil {
				// A duplicate ingest is fine; the node returns success for it.
				return fmt.Errorf("ingest %s->%s %s: %w", m.From, m.To, m.Event.String(), err)
			}
			return nil
		}
	}, dup)
}

// Sync pulls both directions and delivers. With dup it exercises idempotency.
func (w *World) Sync(dup int) error {
	if err := w.PullBoth(); err != nil {
		return err
	}
	return w.Deliver(dup)
}