// Package queue 实现节点间复制事件的可控文件队列。
//
// 目录布局（每个接收节点一个队列根）：
//
//	root/
//	  inbox/   可被节点消费的消息（按序号零填充命名，字典序即交付序）
//	  held/    被控制器滞留的消息（模拟网络分区/延迟，节点不可见）
//	  ack/     已被节点确认处理的消息（用于断言“至少一次”与去重）
//
// 控制器可显式制造：滞留（Hold）、延迟释放（Release）、重复投递（Duplicate）、
// 乱序（Swap 文件名序号）。节点只轮询 inbox，因此 held 中的事件对节点严格不可见，
// 可精确复现“禁用事件尚未到达”这一最小反例前提。
package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"revauth/internal/model"
)

// Queue 单个接收节点的可控队列。
type Queue struct {
	root  string
	inbox string
	held  string
	ack   string
	mu    sync.Mutex
	seq   int64
}

// Open 打开或创建队列目录。
func Open(root string) (*Queue, error) {
	q := &Queue{
		root:  root,
		inbox: filepath.Join(root, "inbox"),
		held:  filepath.Join(root, "held"),
		ack:   filepath.Join(root, "ack"),
	}
	for _, d := range []string{q.inbox, q.held, q.ack} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	return q, nil
}

func (q *Queue) name(seq int64) string {
	return fmt.Sprintf("%012d.json", seq)
}

// Enqueue 把事件放入 inbox，返回消息文件名。
func (q *Queue) Enqueue(ev model.Event) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	name := q.name(q.seq)
	return name, q.writeFile(filepath.Join(q.inbox, name), ev)
}

// Hold 把事件放入 held（节点不可见），用于模拟分区/延迟。
func (q *Queue) Hold(ev model.Event) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	name := q.name(q.seq)
	return name, q.writeFile(filepath.Join(q.held, name), ev)
}

// Release 把 held 中的指定消息移入 inbox，使其对节点可见。
func (q *Queue) Release(name string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	from := filepath.Join(q.held, name)
	to := filepath.Join(q.inbox, name)
	return os.Rename(from, to)
}

// ReleaseAll 释放全部滞留消息（按文件名排序，保证确定性）。
func (q *Queue) ReleaseAll() ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.held)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		if err := os.Rename(filepath.Join(q.held, n), filepath.Join(q.inbox, n)); err != nil {
			return names, err
		}
	}
	return names, nil
}

// Duplicate 复制一条已在 inbox 的消息为新消息，制造重复投递（at-least-once）。
func (q *Queue) Duplicate(existingName string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(q.inbox, existingName))
	if err != nil {
		return "", err
	}
	q.seq++
	name := q.name(q.seq)
	return name, os.WriteFile(filepath.Join(q.inbox, name), b, 0o644)
}

// Reorder 交换两条 inbox 消息的文件名，制造乱序投递。
func (q *Queue) Reorder(a, b string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	pa, pb := filepath.Join(q.inbox, a), filepath.Join(q.inbox, b)
	ba, err := os.ReadFile(pa)
	if err != nil {
		return err
	}
	bb, err := os.ReadFile(pb)
	if err != nil {
		return err
	}
	if err := os.WriteFile(pa, bb, 0o644); err != nil {
		return err
	}
	return os.WriteFile(pb, ba, 0o644)
}

// HeldNames 列出滞留消息（排序）。
func (q *Queue) HeldNames() ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.listJSON(q.held)
}

// Poll 返回 inbox 中按交付序排列的未确认消息。
func (q *Queue) Poll() ([]string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.listJSON(q.inbox)
}

// Read 读取一条 inbox/held 消息内容。
func (q *Queue) Read(dir, name string) (model.Event, error) {
	var ev model.Event
	b, err := os.ReadFile(filepath.Join(q.root, dir, name))
	if err != nil {
		return ev, err
	}
	err = json.Unmarshal(b, &ev)
	return ev, err
}

// Ack 节点成功处理后把消息从 inbox 移入 ack。
func (q *Queue) Ack(name string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	from := filepath.Join(q.inbox, name)
	// 已被并发确认则幂等成功。
	if _, err := os.Stat(from); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.Rename(from, filepath.Join(q.ack, name))
}

// AckCount 返回已确认消息数（测试断言用）。
func (q *Queue) AckCount() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	names, err := q.listJSON(q.ack)
	return len(names), err
}

func (q *Queue) listJSON(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

func (q *Queue) writeFile(path string, ev model.Event) error {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
