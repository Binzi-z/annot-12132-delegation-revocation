package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ccrevoke/internal/event"
	"ccrevoke/internal/scenario"
	"ccrevoke/internal/store"
)

func tempDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	return d
}

func appendAll(t *testing.T, st *store.Store, evs []event.Event) {
	t.Helper()
	for _, e := range evs {
		if _, err := st.Append(e); err != nil && err != store.ErrDuplicate {
			t.Fatalf("append %s: %v", e.String(), err)
		}
	}
}

func TestDurableReplay(t *testing.T) {
	dir := tempDir(t)
	f := scenario.NewFixture()

	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendAll(t, st, f.B.Events)
	head, _ := st.Head()
	st.Close()

	st2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	head2, _ := st2.Head()
	if head != head2 {
		t.Fatalf("head changed across restart: %d != %d", head, head2)
	}
	if got := len(st2.Events()); got != len(f.B.Events) {
		t.Fatalf("event count %d != %d", got, len(f.B.Events))
	}
}

func TestDuplicateIdempotent(t *testing.T) {
	dir := tempDir(t)
	f := scenario.NewFixture()
	st, _ := store.Open(dir)
	defer st.Close()
	appendAll(t, st, f.B.Events)
	head, _ := st.Head()
	if _, err := st.Append(f.B.Events[0]); err != store.ErrDuplicate {
		t.Fatalf("expected duplicate, got %v", err)
	}
	head2, _ := st.Head()
	if head != head2 {
		t.Fatalf("duplicate append changed head")
	}
}

func TestConflictRejected(t *testing.T) {
	dir := tempDir(t)
	f := scenario.NewFixture()
	st, _ := store.Open(dir)
	defer st.Close()
	appendAll(t, st, f.B.Events)
	// Same origin+seq, different content.
	evil := f.B.Events[0]
	evil.Tick += 999
	evil.Sign(f.Reg)
	evil.Prev = f.B.Events[0].Prev
	// Recompute chain: since this is seq 1, prev is "".
	evil.Prev = ""
	evil.Sign(f.Reg)
	if _, err := st.Append(evil); err == nil || err == store.ErrDuplicate {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestCompactionRetainsEvidence(t *testing.T) {
	dir := tempDir(t)
	f := scenario.NewFixture()
	st, _ := store.Open(dir)
	appendAll(t, st, f.B.Events)

	// Add a ban, compact, and verify the ban is retained.
	f.B.Ban(scenario.OrgA, scenario.OrgA, 1, scenario.TenantA, scenario.ResA, scenario.Id(scenario.OrgB, scenario.Bob), "", "emergency")
	ban := f.B.Events[len(f.B.Events)-1]
	if _, err := st.Append(ban); err != nil {
		t.Fatal(err)
	}
	// A dummy state blob is fine for this test.
	raw, _ := json.Marshal(map[string]string{"k": "v"})
	if err := st.Checkpoint(raw, map[string]event.Watermark{}); err != nil {
		t.Fatal(err)
	}
	ev := st.Evidence()
	found := false
	for _, r := range ev {
		if r.EvidenceID == ban.EvidenceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ban evidence lost after compaction: %+v", ev)
	}
	st.Close()

	// Reopen: evidence must still be there.
	st2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	found = false
	for _, r := range st2.Evidence() {
		if r.EvidenceID == ban.EvidenceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("ban evidence lost after reopen")
	}
	if len(st2.Events()) != 0 {
		t.Fatalf("commit log should be empty after compaction, got %d", len(st2.Events()))
	}
}

func TestStaleSnapshotCannotDropEvidence(t *testing.T) {
	// Simulate: snapshot at T0 contains no ban; a ban arrives at T1 and is
	// journaled; a stale snapshot (with the ban removed) is restored; the
	// journal must still win.
	dir := tempDir(t)
	f := scenario.NewFixture()
	st, _ := store.Open(dir)
	appendAll(t, st, f.B.Events)

	raw, _ := json.Marshal(map[string]string{"at": "t0"})
	if err := st.Checkpoint(raw, nil); err != nil {
		t.Fatal(err)
	}

	// Ban after the snapshot.
	f.B.Ban(scenario.OrgA, scenario.OrgA, 1, scenario.TenantA, scenario.ResA, scenario.Id(scenario.OrgB, scenario.Bob), "", "late ban")
	ban := f.B.Events[len(f.B.Events)-1]
	if _, err := st.Append(ban); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// Overwrite the snapshot with a stale one lacking the ban.
	snapPath := filepath.Join(dir, "snapshot.json")
	var snap store.Snapshot
	rawSnap, err := os.ReadFile(snapPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawSnap, &snap); err != nil {
		t.Fatal(err)
	}
	snap.Evidence = nil
	// Recompute state hash so the store accepts it.
	rawBad, _ := json.Marshal(snap.State)
	snap.StateHash = hashHex(rawBad)
	rawSnap, _ = json.Marshal(snap)
	if err := os.WriteFile(snapPath, rawSnap, 0o644); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	found := false
	for _, r := range st2.Evidence() {
		if r.EvidenceID == ban.EvidenceID {
			found = true
		}
	}
	if !found {
		t.Fatalf("stale snapshot dropped a ban that the journal retained")
	}
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}