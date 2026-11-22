package eventlog_test

import (
	"errors"
	"path/filepath"
	"testing"

	"revauth/internal/eventlog"
	"revauth/internal/model"
)

func mkEvent(org model.OrgID, seq uint64, prev string) model.Event {
	ev := model.Event{
		Seq: seq, Issuer: org, Kind: model.EvHeartbeat,
		EmittedAt: 100, Payload: model.HeartbeatPayload{}, PrevHash: prev,
	}
	ev.Hash = ev.Digest()
	return ev
}

// TestAppendAndReplay 正常追加与重放，哈希链完整。
func TestAppendAndReplay(t *testing.T) {
	lg, err := eventlog.Open(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	for i := uint64(1); i <= 4; i++ {
		ev := mkEvent("org-a", i, prev)
		if err := lg.Append(&ev); err != nil {
			t.Fatal(err)
		}
		prev = ev.Hash
	}
	got, err := lg.Replay("org-a")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("want 4 events, got %d", len(got))
	}
	seq, hash := lg.Head("org-a")
	if seq != 4 || hash != prev {
		t.Fatalf("head mismatch seq=%d", seq)
	}
}

// TestGapRejected 乱序/缺口追加必须被拒绝且不破坏既有链。
func TestGapRejected(t *testing.T) {
	lg, err := eventlog.Open(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	ev1 := mkEvent("org-a", 1, "")
	if err := lg.Append(&ev1); err != nil {
		t.Fatal(err)
	}
	bad := mkEvent("org-a", 3, ev1.Hash) // 跳过 seq 2
	if err := lg.Append(&bad); !errors.Is(err, eventlog.ErrChainBroken) {
		t.Fatalf("expected ErrChainBroken, got %v", err)
	}
	got, err := lg.Replay("org-a")
	if err != nil || len(got) != 1 {
		t.Fatalf("chain must remain intact after rejected append: %v len=%d", err, len(got))
	}
}

// TestTruncateKeepsAnchor 压缩截断后保留锚点事件，链仍可校验，
// 且重开日志（模拟重启）后能正确以锚点为链首重放。
func TestTruncateKeepsAnchor(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "log")
	lg, err := eventlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	var prev string
	var evs []model.Event
	for i := uint64(1); i <= 5; i++ {
		ev := mkEvent("org-a", i, prev)
		if err := lg.Append(&ev); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, ev)
		prev = ev.Hash
	}
	// 截断 seq<=3，保留 4、5；其 PrevHash 仍承接历史，重放成功。
	if err := lg.Truncate("org-a", 3); err != nil {
		t.Fatal(err)
	}
	got, err := lg.Replay("org-a")
	if err != nil {
		t.Fatalf("replay after truncate: %v", err)
	}
	if len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 5 {
		t.Fatalf("truncate kept wrong events: %+v", got)
	}
	// 链头哈希不变。
	if _, hash := lg.Head("org-a"); hash != evs[4].Hash {
		t.Fatal("head hash changed after truncation")
	}

	// 重新打开日志（重启），锚点事件 seq=4 作为链首仍可校验。
	lg2, err := eventlog.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got2, err := lg2.Replay("org-a")
	if err != nil {
		t.Fatalf("replay after reopen must anchor at marker: %v", err)
	}
	if len(got2) != 2 || got2[0].Seq != 4 {
		t.Fatalf("reopen replay mismatch: %+v", got2)
	}
}

// TestQuarantineIsolatesFile 隔离把损坏文件移走，签发者回到空链且不影响他人。
func TestQuarantineIsolatesFile(t *testing.T) {
	lg, err := eventlog.Open(filepath.Join(t.TempDir(), "log"))
	if err != nil {
		t.Fatal(err)
	}
	evA := mkEvent("org-a", 1, "")
	if err := lg.Append(&evA); err != nil {
		t.Fatal(err)
	}
	evB := mkEvent("org-b", 1, "")
	if err := lg.Append(&evB); err != nil {
		t.Fatal(err)
	}
	dst, err := lg.Quarantine("org-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lg.Replay("org-a"); err != nil {
		t.Fatalf("quarantined issuer should replay empty, got %v", err)
	}
	gotB, err := lg.Replay("org-b")
	if err != nil || len(gotB) != 1 {
		t.Fatalf("org-b must be unaffected: %v", err)
	}
	if dst == "" {
		t.Fatal("quarantine path empty")
	}
}
