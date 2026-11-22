package engine

import (
	"revauth/internal/eventlog"
	"revauth/internal/model"
)

// buildSnapshot 调用方持写锁，导出当前最少状态为压缩快照。
//
// 紧急禁用（含已解除记录）被完整保留，因此压缩不可能让“已收到的禁用”消失；
// 完整历史被丢弃，只保留判定与审计所需的最少撤销证据。
func (e *Engine) buildSnapshot() *eventlog.Snapshot {
	s := &eventlog.Snapshot{
		Version:       1,
		TakenAt:       e.clock(),
		CurrentGen:    map[string]model.Generation{},
		PubKeys:       map[string][]eventlog.PubKeyEntry{},
		ExitedMembers: map[string][]model.PrincipalID{},
		Watermarks:    map[string]uint64{},
		LastHeartbeat: map[string]int64{},
		LogHeads:      map[string]string{},
	}

	for org, kr := range e.keyrings {
		s.CurrentGen[string(org)] = kr.Current
		var entries []eventlog.PubKeyEntry
		for gen, pub := range kr.PubKeys {
			entries = append(entries, eventlog.PubKeyEntry{
				Generation: gen, PublicKey: append([]byte(nil), pub...),
			})
		}
		s.PubKeys[string(org)] = entries
	}
	for org, set := range e.exited {
		var members []model.PrincipalID
		for m := range set {
			members = append(members, m)
		}
		s.ExitedMembers[string(org)] = members
	}
	// 粘性禁用证据：全部落快照，不做任何裁剪。
	for _, rec := range e.bans {
		s.Bans = append(s.Bans, *rec)
	}
	for org, wm := range e.watermarks {
		s.Watermarks[string(org)] = wm
		_, hash := e.log.Head(org)
		s.LogHeads[string(org)] = hash
	}
	for org, hb := range e.lastHeartbeat {
		s.LastHeartbeat[string(org)] = hb
	}
	return s
}

// Snapshot 导出当前最少状态快照（水位随快照可迁移到其他节点）。
func (e *Engine) Snapshot() *eventlog.Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	// buildSnapshot 只读结构；读锁下安全。
	return e.buildSnapshot()
}

// Compact 执行压缩：
//  1. 写出当前最少状态快照（原子替换）；
//  2. 为每个签发者写入 EvSnapshotMarker 绑定快照摘要并推进链；
//  3. 截断该签发者 marker 及之前的事件，保留后续链。
//
// 重启恢复时先装载快照再重放剩余链，禁用证据无丢失窗口。
func (e *Engine) Compact() (*eventlog.Snapshot, error) {
	e.mu.Lock()
	snap := e.buildSnapshot()
	e.mu.Unlock()

	if err := eventlog.SaveSnapshot(e.root, snap); err != nil {
		return nil, err
	}

	orgs := make([]model.OrgID, 0, len(snap.Watermarks))
	for org := range snap.Watermarks {
		orgs = append(orgs, model.OrgID(org))
	}
	for _, org := range orgs {
		marker := model.SnapshotMarkerPayload{SnapshotHash: snap.Hash()}
		ev, err := e.Emit(org, model.EvSnapshotMarker, marker)
		if err != nil {
			return nil, err
		}
		// 截断 marker 之前的业务事件，但保留 marker 本身作为链锚点：
		// 其 PrevHash 承接被压缩历史、Hash 绑定快照，重启重放不会断链。
		if err := e.log.Truncate(org, ev.Seq-1); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// Watermark 返回某签发者当前可迁移水位。
func (e *Engine) Watermark(org model.OrgID) uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.watermarks[org]
}

// IsQuarantined 报告签发者是否已被故障隔离。
func (e *Engine) IsQuarantined(org model.OrgID) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.quarantined[org]
}

// Bans 返回当前禁用证据的副本（测试与审计用）。
func (e *Engine) Bans() []model.BanRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]model.BanRecord, 0, len(e.bans))
	for _, rec := range e.bans {
		out = append(out, *rec)
	}
	return out
}
