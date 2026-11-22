package main

import (
	"os"
	"path/filepath"
	"testing"

	"ccrevoke/internal/interleave"
)

// TestRunProcessReplay exercises the same two-process replay the CLI runs, so
// the scenario command's logic is covered by the test suite. It writes a
// human-readable transcript to a temp dir and logs its path for inspection.
func TestRunProcessReplay(t *testing.T) {
	var sb transcriptWriter
	old := stdout
	stdout = &sb
	defer func() { stdout = old }()

	v, states := interleave.Enumerate(4)
	if v != nil {
		t.Fatalf("enumeration violation after %d states: %v", states, *v)
	}
	if err := runProcessReplay(false); err != nil {
		t.Fatalf("process replay failed: %v", err)
	}

	path := filepath.Join(t.TempDir(), "transcript.txt")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		t.Fatalf("write transcript: %v", err)
	}
	t.Logf("transcript written to %s (%d bytes)", path, len(sb.String()))
}
