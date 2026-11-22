// Package eventlog 实现按签发者分区的持久化哈希链事件日志。
//
// 磁盘布局（root 目录）：
//
//	root/
//	  events/<org>.log          每个签发者一条独立 JSONL 哈希链
//	  events/<org>.quarantine   链损坏后隔离的现场文件
//	  snapshot.json             最近一次压缩快照（原子替换）
//
// 故障隔离：任一签发者的链损坏只会隔离该文件，另一签发者的链照常服务。
package eventlog

import (
	"bufio"
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

// ErrChainBroken 哈希链校验失败（缺口、乱序、摘要不符）。
var ErrChainBroken = errors.New("eventlog: hash chain broken")

// Log 管理多个签发者分区的追加式日志。
type Log struct {
	root string
	mu   sync.Mutex
	// heads 记录每个签发者链尾哈希与最大序号（内存中的链头）。
	heads map[model.OrgID]head
}

type head struct {
	lastHash string
	lastSeq  uint64
}

// Open 打开（或创建）日志目录。
func Open(root string) (*Log, error) {
	if err := os.MkdirAll(filepath.Join(root, "events"), 0o755); err != nil {
		return nil, err
	}
	l := &Log{root: root, heads: map[model.OrgID]head{}}
	return l, nil
}

func (l *Log) path(org model.OrgID) string {
	return filepath.Join(l.root, "events", sanitize(string(org))+".log")
}

func sanitize(name string) string {
	r := strings.NewReplacer("..", "_", string(filepath.Separator), "_", "/", "_", "\\", "_")
	return r.Replace(name)
}

// Append 追加一个事件。调用方需已填好 Seq/Issuer/Kind/Payload/EmittedAt；
// 本方法负责补齐 PrevHash/Hash 并持久化（fsync 后返回）。
// Seq 必须等于该签发者当前尾序号 + 1，否则返回链错误且不写入。
func (l *Log) Append(ev *model.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	h := l.heads[ev.Issuer]
	if ev.Seq != h.lastSeq+1 {
		return fmt.Errorf("%w: issuer=%s expect seq=%d got=%d",
			ErrChainBroken, ev.Issuer, h.lastSeq+1, ev.Seq)
	}
	ev.PrevHash = h.lastHash
	ev.Hash = ev.Digest()

	f, err := os.OpenFile(l.path(ev.Issuer), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	l.heads[ev.Issuer] = head{lastHash: ev.Hash, lastSeq: ev.Seq}
	return nil
}

// Replay 读取并完整校验某签发者的链，返回有序事件。
// 校验内容：序号连续、PrevHash 相接、Hash 摘要一致。
func (l *Log) Replay(org model.OrgID) ([]model.Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.readLocked(org)
}

func (l *Log) readLocked(org model.OrgID) ([]model.Event, error) {
	f, err := os.Open(l.path(org))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var events []model.Event
	var prevHash string
	var prevSeq uint64
	anchored := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var ev model.Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("%w: %s line %d unmarshal: %v", ErrChainBroken, org, line, err)
		}
		// 压缩截断后，文件首事件是 EvSnapshotMarker 链锚点：它的 PrevHash 指向
		// 已被快照承载的历史，因此首个事件不校验前驱，只自校摘要，其后正常链接。
		if !anchored && ev.Seq > 1 {
			if got := ev.Digest(); got != ev.Hash {
				return nil, fmt.Errorf("%w: %s anchor line %d digest mismatch", ErrChainBroken, org, line)
			}
			events = append(events, ev)
			prevHash, prevSeq, anchored = ev.Hash, ev.Seq, true
			continue
		}
		if ev.Seq != prevSeq+1 {
			return nil, fmt.Errorf("%w: %s line %d seq gap want=%d got=%d",
				ErrChainBroken, org, line, prevSeq+1, ev.Seq)
		}
		if ev.PrevHash != prevHash {
			return nil, fmt.Errorf("%w: %s line %d prevhash mismatch", ErrChainBroken, org, line)
		}
		if got := ev.Digest(); got != ev.Hash {
			return nil, fmt.Errorf("%w: %s line %d digest mismatch", ErrChainBroken, org, line)
		}
		events = append(events, ev)
		prevHash = ev.Hash
		prevSeq = ev.Seq
		anchored = true
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	l.heads[org] = head{lastHash: prevHash, lastSeq: prevSeq}
	return events, nil
}

// Quarantine 在链损坏时把现场文件改名隔离，使该签发者停止服务，
// 而其他签发者文件不受影响。返回隔离后的路径。
func (l *Log) Quarantine(org model.OrgID) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	src := l.path(org)
	dst := src + ".quarantine"
	if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	delete(l.heads, org)
	return dst, nil
}

// Truncate 压缩：丢弃该签发者序号 <= keepSeq 的事件，保留剩余链。
// 被保留的第一条事件其 PrevHash 仍指向被压缩历史，调用方应在其后
// 写入 EvSnapshotMarker 并由快照承载被压缩状态。采用临时文件+原子改名。
func (l *Log) Truncate(org model.OrgID, keepSeq uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.readLocked(org)
	if err != nil {
		return err
	}
	tmp := l.path(org) + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(out)
	for _, ev := range events {
		if ev.Seq <= keepSeq {
			continue
		}
		b, err := json.Marshal(ev)
		if err != nil {
			out.Close()
			return err
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			out.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, l.path(org)); err != nil {
		return err
	}
	// 重新校准内存链头。
	_, err = l.readLocked(org)
	return err
}

// Issuers 返回当前拥有日志文件的签发者（排序，保证确定性）。
func (l *Log) Issuers() ([]model.OrgID, error) {
	entries, err := os.ReadDir(filepath.Join(l.root, "events"))
	if err != nil {
		return nil, err
	}
	var out []model.OrgID
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".log") {
			continue
		}
		out = append(out, model.OrgID(strings.TrimSuffix(name, ".log")))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// Head 返回某签发者当前链尾（序号与哈希）。
func (l *Log) Head(org model.OrgID) (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.heads[org]
	return h.lastSeq, h.lastHash
}
