package queue_test

import (
	"path/filepath"
	"testing"

	"revauth/internal/model"
	"revauth/internal/queue"
)

func TestHoldReleaseAndDuplicate(t *testing.T) {
	q, err := queue.Open(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}
	ev := model.Event{Seq: 1, Issuer: "org-a", Kind: model.EvHeartbeat, Payload: model.HeartbeatPayload{}}
	ev.Hash = ev.Digest()

	// 滞留消息对 Poll 不可见。
	held, err := q.Hold(ev)
	if err != nil {
		t.Fatal(err)
	}
	if names, _ := q.Poll(); len(names) != 0 {
		t.Fatalf("held message must not be visible, got %v", names)
	}
	heldNames, _ := q.HeldNames()
	if len(heldNames) != 1 || heldNames[0] != held {
		t.Fatalf("held names mismatch: %v", heldNames)
	}

	// 释放后可见并可确认。
	if err := q.Release(held); err != nil {
		t.Fatal(err)
	}
	names, _ := q.Poll()
	if len(names) != 1 {
		t.Fatalf("released message must be visible, got %v", names)
	}
	if err := q.Ack(names[0]); err != nil {
		t.Fatal(err)
	}
	if c, _ := q.AckCount(); c != 1 {
		t.Fatalf("ack count = %d", c)
	}

	// 重复投递：新消息进入 inbox，确认后 ack 数增加（引擎侧负责幂等去重）。
	dup, err := q.Duplicate(names[0])
	if err != nil {
		t.Fatal(err)
	}
	if dup == names[0] {
		t.Fatal("duplicate must get a new message name")
	}
	poll, _ := q.Poll()
	if len(poll) != 1 {
		t.Fatalf("duplicate should be pending in inbox, got %d", len(poll))
	}
}

func TestReorder(t *testing.T) {
	q, err := queue.Open(filepath.Join(t.TempDir(), "q"))
	if err != nil {
		t.Fatal(err)
	}
	e1 := model.Event{Seq: 1, Issuer: "org-a", Kind: model.EvHeartbeat, Payload: model.HeartbeatPayload{}}
	e1.Hash = e1.Digest()
	e2 := model.Event{Seq: 2, Issuer: "org-a", Kind: model.EvHeartbeat, Payload: model.HeartbeatPayload{}}
	e2.Hash = e2.Digest()
	n1, _ := q.Enqueue(e1)
	n2, _ := q.Enqueue(e2)
	if err := q.Reorder(n1, n2); err != nil {
		t.Fatal(err)
	}
	// 文件名顺序不变，但内容互换：Poll 第一项现在承载 seq=2（乱序投递）。
	names, _ := q.Poll()
	first, err := q.Read("inbox", names[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq != 2 {
		t.Fatalf("expected reordered first event seq=2, got %d", first.Seq)
	}
}
