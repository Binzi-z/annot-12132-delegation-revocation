// Package engine 是授权回收协议的判定核心。
//
// 它在持久化事件日志之上维护“最少撤销证据”，对可独立验证的准入证书做
// 多路径准入判定，并为每次决策输出可核查依据。所有状态均可由
// 快照 + 压缩后日志重建，水位随快照在节点间迁移。
package engine

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"revauth/internal/crypto"
	"revauth/internal/eventlog"
	"revauth/internal/model"
)

// 默认只读分区宽限期（秒）。宽限期内的读可降级放行，超时即拒绝。
const DefaultReadGraceSeconds int64 = 30

// ErrAlreadyApplied 事件序号落后于本签发者水位（重复投递），幂等忽略信号。
var ErrAlreadyApplied = errors.New("engine: event already applied")

// ErrGap 收到的事件存在序号缺口，调用方应继续等待前驱事件，不得跳号。
var ErrGap = errors.New("engine: event sequence gap")

// Engine 单节点判定引擎。
type Engine struct {
	mu sync.RWMutex

	root      string
	log       *eventlog.Log
	clock     func() int64
	readGrace int64
	audit     *AuditWriter

	// 每个签发者分区独立维护的状态：任一分区故障不波及其他分区。
	keyrings      map[model.OrgID]*crypto.Keyring
	exited        map[model.OrgID]map[model.PrincipalID]bool
	watermarks    map[model.OrgID]uint64
	lastHeartbeat map[model.OrgID]int64
	quarantined   map[model.OrgID]bool
	// 链已知但尚未收到创始换主事件（无公钥）的签发者。
	bootstrapped map[model.OrgID]bool

	// 跨签发者的粘性禁用证据（含已解除记录，防止重放旧禁用/旧证书）。
	bans map[model.BanKey]*model.BanRecord
}

// Option 引擎构造选项。
type Option func(*Engine)

// WithClock 注入时钟（测试用确定性时间）。
func WithClock(c func() int64) Option {
	return func(e *Engine) { e.clock = c }
}

// WithReadGrace 设置读分区宽限期。
func WithReadGrace(seconds int64) Option {
	return func(e *Engine) { e.readGrace = seconds }
}

// WithAudit 开启决策审计落盘。
func WithAudit(w *AuditWriter) Option {
	return func(e *Engine) { e.audit = w }
}

// Open 打开或重建引擎：先装载快照，再重放压缩后剩余日志。
// 单个签发者日志损坏时隔离该签发者，其余签发者正常恢复。
func Open(root string, opts ...Option) (*Engine, error) {
	lg, err := eventlog.Open(root)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		root:          root,
		log:           lg,
		clock:         func() int64 { return time.Now().Unix() },
		readGrace:     DefaultReadGraceSeconds,
		keyrings:      map[model.OrgID]*crypto.Keyring{},
		exited:        map[model.OrgID]map[model.PrincipalID]bool{},
		watermarks:    map[model.OrgID]uint64{},
		lastHeartbeat: map[model.OrgID]int64{},
		quarantined:   map[model.OrgID]bool{},
		bootstrapped:  map[model.OrgID]bool{},
		bans:          map[model.BanKey]*model.BanRecord{},
	}
	for _, o := range opts {
		o(e)
	}

	snap, err := eventlog.LoadSnapshot(root)
	if err != nil && !errors.Is(err, eventlog.ErrNoSnapshot) {
		return nil, err
	}
	if snap != nil {
		if err := e.restoreSnapshot(snap); err != nil {
			return nil, err
		}
	}

	issuers, err := lg.Issuers()
	if err != nil {
		return nil, err
	}
	for _, org := range issuers {
		evs, err := lg.Replay(org)
		if err != nil {
			// 故障隔离：隔离该签发者现场，继续恢复其他签发者。
			if qerr := e.quarantine(org); qerr != nil {
				return nil, qerr
			}
			continue
		}
		for i := range evs {
			ev := evs[i]
			if snap != nil && ev.Seq <= e.watermarks[org] {
				continue // 已包含在快照中
			}
			if err := e.apply(&ev); err != nil {
				return nil, fmt.Errorf("replay issuer=%s seq=%d: %w", org, ev.Seq, err)
			}
		}
	}
	return e, nil
}

// restoreSnapshot 从快照重建最少状态（可迁移水位随之恢复）。
func (e *Engine) restoreSnapshot(s *eventlog.Snapshot) error {
	for org, gen := range s.CurrentGen {
		orgID := model.OrgID(org)
		kr := crypto.NewKeyring()
		for _, entry := range s.PubKeys[org] {
			if err := kr.Rotate(entry.Generation, entry.PublicKey); err != nil {
				return err
			}
		}
		if kr.Current != gen {
			return fmt.Errorf("snapshot keyring current mismatch for %s", org)
		}
		e.keyrings[orgID] = kr
		e.bootstrapped[orgID] = true
	}
	for org, members := range s.ExitedMembers {
		set := map[model.PrincipalID]bool{}
		for _, m := range members {
			set[m] = true
		}
		e.exited[model.OrgID(org)] = set
	}
	for i := range s.Bans {
		b := s.Bans[i]
		key := model.BanKey{Tenant: b.Tenant, Resource: b.Resource, Subject: b.Subject}
		cp := b
		e.bans[key] = &cp
	}
	for org, wm := range s.Watermarks {
		e.watermarks[model.OrgID(org)] = wm
	}
	for org, hb := range s.LastHeartbeat {
		e.lastHeartbeat[model.OrgID(org)] = hb
	}
	return nil
}

// Emit 构造并持久化一个新事件，随后应用到内存状态。
func (e *Engine) Emit(org model.OrgID, kind model.EventKind, payload any) (*model.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.quarantined[org] {
		return nil, fmt.Errorf("issuer %s is quarantined", org)
	}
	seq := e.watermarks[org] + 1
	ev := &model.Event{
		Seq:       seq,
		Issuer:    org,
		Kind:      kind,
		EmittedAt: e.clock(),
		Payload:   payload,
	}
	if err := e.log.Append(ev); err != nil {
		return nil, err
	}
	if err := e.apply(ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// Ingest 接收外部（队列复制）事件：校验序号连续性后持久化并应用。
// 重复事件返回 ErrAlreadyApplied；缺口返回 ErrGap，均不产生副作用。
//
// 事件必须携带完整哈希链（Seq 连续、PrevHash 相接、Hash 正确），
// 适用于节点间复制场景。
func (e *Engine) Ingest(ev model.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.quarantined[ev.Issuer] {
		return fmt.Errorf("issuer %s is quarantined", ev.Issuer)
	}
	if got := ev.Digest(); got != ev.Hash {
		if qerr := e.quarantineLocked(ev.Issuer); qerr != nil {
			return qerr
		}
		return fmt.Errorf("%w: digest mismatch, issuer quarantined", eventlog.ErrChainBroken)
	}
	wm := e.watermarks[ev.Issuer]
	if ev.Seq <= wm {
		return ErrAlreadyApplied
	}
	if ev.Seq != wm+1 {
		return fmt.Errorf("%w: issuer=%s watermark=%d got=%d", ErrGap, ev.Issuer, wm, ev.Seq)
	}
	toAppend := ev
	if err := e.log.Append(&toAppend); err != nil {
		if errors.Is(err, eventlog.ErrChainBroken) {
			_ = e.quarantineLocked(ev.Issuer)
		}
		return err
	}
	return e.apply(&toAppend)
}

// IngestUnchained 接收不维护哈希链的轻量客户端（如 HTTP 控制面）提交的事件：
// 由本节点按当前水位与链头补齐 Seq/PrevHash/Hash 后再持久化。
// 重复语义仍由水位保证；适用于可信控制面注入，复制路径仍应使用 Ingest。
func (e *Engine) IngestUnchained(kind model.EventKind, issuer model.OrgID, payload any) (*model.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.quarantined[issuer] {
		return nil, fmt.Errorf("issuer %s is quarantined", issuer)
	}
	wm := e.watermarks[issuer]
	_, headHash := e.log.Head(issuer)
	ev := &model.Event{
		Seq: wm + 1, Issuer: issuer, Kind: kind,
		EmittedAt: e.clock(), Payload: payload, PrevHash: headHash,
	}
	if err := e.log.Append(ev); err != nil {
		if errors.Is(err, eventlog.ErrChainBroken) {
			_ = e.quarantineLocked(issuer)
		}
		return nil, err
	}
	if err := e.apply(ev); err != nil {
		return nil, err
	}
	return ev, nil
}

// apply 将单个事件应用到内存状态并推进水位。调用方持锁。
func (e *Engine) apply(ev *model.Event) error {
	switch ev.Kind {
	case model.EvKeyRotated:
		p, ok := ev.Payload.(model.KeyRotatedPayload)
		if !ok {
			return typeMismatch(ev)
		}
		kr, exists := e.keyrings[ev.Issuer]
		if !exists {
			kr = crypto.NewKeyring()
			e.keyrings[ev.Issuer] = kr
		}
		if err := kr.Rotate(p.NewGeneration, p.PublicKey); err != nil {
			return err
		}
		e.bootstrapped[ev.Issuer] = true

	case model.EvMemberExited:
		p, ok := ev.Payload.(model.MemberExitedPayload)
		if !ok {
			return typeMismatch(ev)
		}
		set := e.exited[ev.Issuer]
		if set == nil {
			set = map[model.PrincipalID]bool{}
			e.exited[ev.Issuer] = set
		}
		set[p.Member] = true

	case model.EvMemberRejoined:
		p, ok := ev.Payload.(model.MemberRejoinedPayload)
		if !ok {
			return typeMismatch(ev)
		}
		if set := e.exited[ev.Issuer]; set != nil {
			delete(set, p.Member)
		}

	case model.EvEmergencyBan:
		p, ok := ev.Payload.(model.EmergencyBanPayload)
		if !ok {
			return typeMismatch(ev)
		}
		key := model.BanKey{Tenant: p.Tenant, Resource: p.Resource, Subject: p.Subject}
		// 粘性：重复禁用保持幂等，已存在记录不被覆盖（保留最早禁用时间）。
		if existing, seen := e.bans[key]; seen && !existing.Lifted {
			break
		}
		e.bans[key] = &model.BanRecord{
			Tenant: p.Tenant, Resource: p.Resource, Subject: p.Subject,
			IssuedBy: ev.Issuer, BannedAt: ev.EmittedAt, Reason: p.Reason,
		}

	case model.EvBanLifted:
		p, ok := ev.Payload.(model.BanLiftedPayload)
		if !ok {
			return typeMismatch(ev)
		}
		key := model.BanKey{Tenant: p.Tenant, Resource: p.Resource, Subject: p.Subject}
		rec, seen := e.bans[key]
		if !seen {
			return fmt.Errorf("ban lift without matching ban: %+v", key)
		}
		rec.Lifted = true
		rec.LiftedAt = ev.EmittedAt
		rec.LiftedBy = ev.Issuer

	case model.EvHeartbeat:
		if _, ok := ev.Payload.(model.HeartbeatPayload); !ok {
			return typeMismatch(ev)
		}
		e.lastHeartbeat[ev.Issuer] = ev.EmittedAt

	case model.EvSnapshotMarker:
		if _, ok := ev.Payload.(model.SnapshotMarkerPayload); !ok {
			return typeMismatch(ev)
		}
		// 分界标记不改变业务状态，仅推进水位。

	default:
		return fmt.Errorf("unknown event kind %q", ev.Kind)
	}

	e.watermarks[ev.Issuer] = ev.Seq
	return nil
}

func typeMismatch(ev *model.Event) error {
	return fmt.Errorf("event %s seq %d payload type mismatch", ev.Kind, ev.Seq)
}

// quarantine / quarantineLocked 隔离故障签发者：移走损坏日志并标记，
// 该签发者相关访问一律拒绝，其他签发者不受影响。
func (e *Engine) quarantine(org model.OrgID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.quarantineLocked(org)
}

func (e *Engine) quarantineLocked(org model.OrgID) error {
	if _, err := e.log.Quarantine(org); err != nil {
		return err
	}
	e.quarantined[org] = true
	return nil
}
