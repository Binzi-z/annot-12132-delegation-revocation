// Package store implements a durable node store: an append-only event log, a
// local commit chain, a retained evidence journal, and snapshots with
// compaction.
//
// Durability model
//
//   - log.jsonl holds accepted events (canonical JSON) in local acceptance
//     order. Every append is fsynced before the append is reported as done.
//   - commits.jsonl holds the local acceptance chain: each commit binds the
//     previous commit hash and the accepted event hash. A node's view of the
//     world is a prefix of this chain.
//   - evidence.jsonl is an append-only journal of revocation evidence. It is
//     never truncated by compaction; compaction only deduplicates it.
//   - snapshot.json holds a checkpoint of model state plus the evidence and
//     watermark sets. Restoring a *stale* snapshot is safe because the fold
//     re-applies the durable evidence union on top of it.
package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"ccrevoke/internal/event"
)

const (
	commitName   = "commits.jsonl"
	evidenceName = "evidence.jsonl"
	snapName     = "snapshot.json"
	formatVer    = 1
)

// Commit is one entry in the local acceptance chain.
type Commit struct {
	Pos       uint64      `json:"pos"`
	Prev      string      `json:"prev"`
	EventHash string      `json:"event_hash"`
	Event     event.Event `json:"event"`
	Hash      string      `json:"hash"`
}

// computeHash derives the commit hash from its predecessors and event hash.
func (c Commit) computeHash() string {
	raw, _ := json.Marshal(struct {
		Pos       uint64 `json:"pos"`
		Prev      string `json:"prev"`
		EventHash string `json:"event_hash"`
	}{c.Pos, c.Prev, c.EventHash})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// OriginMark is the highest accepted (seq, hash) per origin node. It is
// persisted in the snapshot so a node can keep extending its own event chain
// after compaction and restart.
type OriginMark struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// Snapshot is the on-disk checkpoint.
type Snapshot struct {
	Version    int                                  `json:"version"`
	Pos        uint64                               `json:"pos"`
	LastCommit string                               `json:"last_commit"`
	Evidence   []event.EvidenceRecord               `json:"evidence"`
	Watermarks map[string]event.Watermark           `json:"watermarks"`
	Origins    map[string]OriginMark                `json:"origins"`
	StateHash  string                               `json:"state_hash"`
	State      json.RawMessage                      `json:"state"`
}

// Store is a durable, concurrency-safe node store.
type Store struct {
	mu sync.Mutex
	dir string

	logFile *os.File
	evFile  *os.File

	commits  []Commit                     // retained commits (after snapshot pos)
	byOrigin map[string]map[uint64]string // origin node -> seq -> hash
	origins  map[string]OriginMark
	headPos  uint64
	headHash string

	snap    *Snapshot
	evid    []event.EvidenceRecord
	evidSet map[string]struct{}
}

// Open loads (or initialises) a store rooted at dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		dir:      dir,
		byOrigin: map[string]map[uint64]string{},
		origins:  map[string]OriginMark{},
		evidSet:  map[string]struct{}{},
	}

	if err := s.loadSnapshot(); err != nil {
		return nil, err
	}
	if err := s.loadEvidence(); err != nil {
		return nil, err
	}
	if err := s.loadLog(); err != nil {
		return nil, err
	}
	if err := s.reopenAppenders(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) loadSnapshot() error {
	raw, err := os.ReadFile(s.path(snapName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return fmt.Errorf("store: corrupt snapshot: %w", err)
	}
	if snap.Version != formatVer {
		return fmt.Errorf("store: unsupported snapshot version %d", snap.Version)
	}
	sum := sha256.Sum256(snap.State)
	if hex.EncodeToString(sum[:]) != snap.StateHash {
		return fmt.Errorf("store: snapshot state hash mismatch")
	}
	s.snap = &snap
	s.headPos = snap.Pos
	s.headHash = snap.LastCommit
	if snap.Origins != nil {
		s.origins = snap.Origins
	}
	return nil
}

func (s *Store) loadEvidence() error {
	f, err := os.Open(s.path(evidenceName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	recs, err := readRecords(f)
	if err != nil {
		return err
	}
	s.evid = event.MergeEvidence(s.evid, recs)
	for _, r := range s.evid {
		s.evidSet[r.EvidenceID] = struct{}{}
	}
	return nil
}

func readRecords(r io.Reader) ([]event.EvidenceRecord, error) {
	var out []event.EvidenceRecord
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec event.EvidenceRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func (s *Store) loadLog() error {
	f, err := os.Open(s.path(commitName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	prevPos := s.headPos
	prevHash := s.headHash
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var c Commit
		if err := json.Unmarshal(line, &c); err != nil {
			return fmt.Errorf("store: corrupt commit: %w", err)
		}
		if c.Pos != prevPos+1 {
			return fmt.Errorf("store: commit position gap: got %d want %d", c.Pos, prevPos+1)
		}
		if c.Prev != prevHash {
			return fmt.Errorf("store: commit chain break at pos %d", c.Pos)
		}
		if c.computeHash() != c.Hash {
			return fmt.Errorf("store: commit hash mismatch at pos %d", c.Pos)
		}
		if !c.Event.VerifyHash() {
			return fmt.Errorf("store: event hash mismatch at pos %d", c.Pos)
		}
		s.commits = append(s.commits, c)
		s.noteOrigin(c.Event)
		prevPos, prevHash = c.Pos, c.Hash
	}
	if err := sc.Err(); err != nil {
		return err
	}
	s.headPos, s.headHash = prevPos, prevHash
	return nil
}

func (s *Store) noteOrigin(e event.Event) {
	m, ok := s.byOrigin[e.Node]
	if !ok {
		m = map[uint64]string{}
		s.byOrigin[e.Node] = m
	}
	m[e.Seq] = e.Hash
	if cur, ok := s.origins[e.Node]; !ok || e.Seq > cur.Seq {
		s.origins[e.Node] = OriginMark{Seq: e.Seq, Hash: e.Hash}
	}
}

// OriginMark returns the highest-seen (seq, hash) for an origin, if any.
func (s *Store) OriginMark(origin string) (OriginMark, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.origins[origin]
	return m, ok
}

// OriginMarks returns a copy of all origin marks.
func (s *Store) OriginMarks() map[string]OriginMark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]OriginMark, len(s.origins))
	for k, v := range s.origins {
		out[k] = v
	}
	return out
}

// Origins returns a copy of all origin marks (internal helper).
func (s *Store) Origins() map[string]OriginMark { return s.OriginMarks() }

func copyMarks(in map[string]OriginMark) map[string]OriginMark {
	out := make(map[string]OriginMark, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s *Store) reopenAppenders() error {
	lf, err := os.OpenFile(s.path(commitName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	ef, err := os.OpenFile(s.path(evidenceName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		lf.Close()
		return err
	}
	s.logFile, s.evFile = lf, ef
	return nil
}

// Close releases file handles.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if s.logFile != nil {
		first = s.logFile.Close()
		s.logFile = nil
	}
	if s.evFile != nil {
		if err := s.evFile.Close(); err != nil && first == nil {
			first = err
		}
		s.evFile = nil
	}
	return first
}

// ErrDuplicate is returned when an event is already present (idempotent import).
var ErrDuplicate = errors.New("store: duplicate event")

// Append durably accepts an event. It is idempotent per (origin node, seq).
func (s *Store) Append(ev event.Event) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Node == "" || ev.Seq == 0 {
		return 0, errors.New("store: event missing origin or sequence")
	}
	if !ev.VerifyHash() {
		return 0, errors.New("store: event hash mismatch")
	}
	if m := s.byOrigin[ev.Node]; m != nil {
		if h, ok := m[ev.Seq]; ok {
			if h == ev.Hash {
				return 0, ErrDuplicate
			}
			return 0, fmt.Errorf("store: origin %s seq %d conflicting hash", ev.Node, ev.Seq)
		}
	}
	// After a compaction the exact per-seq map is gone, but the persisted origin
	// mark still tells us the event was already folded into the snapshot. Treat
	// any seq at or below the mark as a duplicate so a stale replay cannot regrow
	// the log; the stored snapshot already reflects it.
	if m, ok := s.origins[ev.Node]; ok && ev.Seq <= m.Seq {
		return 0, ErrDuplicate
	}
	c := Commit{Pos: s.headPos + 1, Prev: s.headHash, EventHash: ev.Hash, Event: ev}
	c.Hash = c.computeHash()

	line, err := json.Marshal(c)
	if err != nil {
		return 0, err
	}
	line = append(line, '\n')
	if _, err := s.logFile.Write(line); err != nil {
		return 0, err
	}
	if err := s.logFile.Sync(); err != nil {
		return 0, err
	}

	if ev.Evidence() {
		rec := event.FromEvent(ev)
		el, err := json.Marshal(rec)
		if err != nil {
			return 0, err
		}
		el = append(el, '\n')
		if _, err := s.evFile.Write(el); err != nil {
			return 0, err
		}
		if err := s.evFile.Sync(); err != nil {
			return 0, err
		}
		s.evid = event.MergeEvidence(s.evid, []event.EvidenceRecord{rec})
		s.evidSet[rec.EvidenceID] = struct{}{}
	}

	s.commits = append(s.commits, c)
	s.noteOrigin(ev)
	s.headPos = c.Pos
	s.headHash = c.Hash
	return c.Pos, nil
}

// Head returns the current local position and commit hash.
func (s *Store) Head() (uint64, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headPos, s.headHash
}

// NextSeq returns the next unused sequence number for an origin node. Each node
// authors events under its own origin only; peers' sequences are tracked so
// replication can request gaps precisely. The persisted origin mark keeps this
// correct across compaction and restart.
func (s *Store) NextSeq(origin string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var max uint64
	for seq := range s.byOrigin[origin] {
		if seq > max {
			max = seq
		}
	}
	if m, ok := s.origins[origin]; ok && m.Seq > max {
		max = m.Seq
	}
	return max + 1
}

// HasOrigin reports whether an (origin, seq) event is already accepted. After
// compaction the exact seq is remembered only up to the origin mark, so any seq
// at or below the mark is treated as accepted (the store dedupes by hash when
// it does see the event again).
func (s *Store) HasOrigin(origin string, seq uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byOrigin[origin][seq]; ok {
		return true
	}
	if m, ok := s.origins[origin]; ok && seq <= m.Seq {
		return true
	}
	return false
}

// MissingFrom returns, per origin, the sequence numbers below highest that the
// store has not yet accepted. Used to request a precise retransmission.
func (s *Store) MissingFrom(origin string, highest uint64) []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	mark := s.origins[origin]
	var out []uint64
	for seq := mark.Seq + 1; seq <= highest; seq++ {
		if _, ok := s.byOrigin[origin][seq]; !ok {
			out = append(out, seq)
		}
	}
	return out
}

// Events returns all retained events (snapshot prefix excluded) in acceptance
// order.
func (s *Store) Events() []event.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]event.Event, len(s.commits))
	for i, c := range s.commits {
		out[i] = c.Event
	}
	return out
}

// Commits returns the retained commit slice.
func (s *Store) Commits() []Commit {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Commit(nil), s.commits...)
}

// Snapshot returns the current loaded snapshot (may be nil).
func (s *Store) Snapshot() *Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap == nil {
		return nil
	}
	cp := *s.snap
	return &cp
}

// Evidence returns the deduplicated, durable evidence union.
func (s *Store) Evidence() []event.EvidenceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]event.EvidenceRecord(nil), s.evid...)
}

// EvidenceSet returns evidence keyed by EvidenceID.
func (s *Store) EvidenceSet() map[string]event.EvidenceRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]event.EvidenceRecord, len(s.evid))
	for _, r := range s.evid {
		out[r.EvidenceID] = r
	}
	return out
}

// Checkpoint writes a snapshot of state at the current head, then compacts the
// commit log and evidence journal. state must be the serialized model at head.
func (s *Store) Checkpoint(state json.RawMessage, watermarks map[string]event.Watermark) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	snapEvidence := event.MergeEvidence(s.snapEvidence(), s.evidenceFromCommits(), s.evid)
	canon, err := compactJSON(state)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(canon)
	snap := Snapshot{
		Version:    formatVer,
		Pos:        s.headPos,
		LastCommit: s.headHash,
		Evidence:   snapEvidence,
		Watermarks: event.MaxWatermarks(s.snapWatermarks(), watermarks),
		Origins:    copyMarks(s.origins),
		StateHash:  hex.EncodeToString(sum[:]),
		State:      canon,
	}
	if err := s.writeSnapshot(&snap); err != nil {
		return err
	}
	if err := s.compactFiles(snapEvidence); err != nil {
		return err
	}
	s.snap = &snap
	s.commits = nil
	s.evid = snapEvidence
	s.evidSet = map[string]struct{}{}
	for _, r := range snapEvidence {
		s.evidSet[r.EvidenceID] = struct{}{}
	}
	return nil
}

func (s *Store) snapEvidence() []event.EvidenceRecord {
	if s.snap == nil {
		return nil
	}
	return s.snap.Evidence
}

func (s *Store) snapWatermarks() map[string]event.Watermark {
	if s.snap == nil {
		return nil
	}
	return s.snap.Watermarks
}

func (s *Store) evidenceFromCommits() []event.EvidenceRecord {
	var out []event.EvidenceRecord
	for _, c := range s.commits {
		if c.Event.Evidence() {
			out = append(out, event.FromEvent(c.Event))
		}
	}
	return out
}

func (s *Store) writeSnapshot(snap *Snapshot) error {
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	tmp := s.path(snapName + ".tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	if err := fsyncFile(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(snapName)); err != nil {
		return err
	}
	return fsyncDir(s.dir)
}

// compactJSON re-encodes raw JSON in a canonical, whitespace-free form so the
// hash stored alongside it matches byte-for-byte content that survives
// re-encoding on load.
func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return json.RawMessage(buf.Bytes()), nil
}

// compactFiles truncates the commit log and rewrites the evidence journal to
// the minimal union. Only the snapshot (written first) can duplicate evidence,
// so a crash between the two steps cannot lose evidence.
func (s *Store) compactFiles(evidence []event.EvidenceRecord) error {
	if s.logFile != nil {
		s.logFile.Close()
		s.logFile = nil
	}
	if s.evFile != nil {
		s.evFile.Close()
		s.evFile = nil
	}

	if err := truncate(s.path(commitName)); err != nil {
		return err
	}

	var buf bytes.Buffer
	for _, r := range evidence {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		buf.Write(raw)
		buf.WriteByte('\n')
	}
	if err := writeFileSync(s.path(evidenceName), buf.Bytes()); err != nil {
		return err
	}
	return s.reopenAppenders()
}

func truncate(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := fsyncFile(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(path))
}

func fsyncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func fsyncDir(dir string) error {
	// Windows does not support fsync on directories; ignore the error there.
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	_ = d.Sync()
	return nil
}

// SortedIssuers returns the issuers seen in evidence, for diagnostics.
func SortedIssuers(ev []event.EvidenceRecord) []string {
	set := map[string]struct{}{}
	for _, r := range ev {
		if r.Issuer != "" {
			set[r.Issuer] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}