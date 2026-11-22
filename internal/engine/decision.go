package engine

import (
	"revauth/internal/model"
)

// Check 单条候选路径的完整核查记录，构成决策的可核查依据。
type Check struct {
	PathIndex int            `json:"path_index"`
	Issuers   []model.OrgID  `json:"issuers"`
	Valid     bool           `json:"valid"`
	Reason    string         `json:"reason"`
	Details   []EdgeEvidence `json:"details"`
}

// EdgeEvidence 每条委派边的独立验证证据。
type EdgeEvidence struct {
	Issuer      model.OrgID       `json:"issuer"`
	Generation  model.Generation  `json:"generation"`
	From        model.PrincipalID `json:"from"`
	To          model.PrincipalID `json:"to"`
	SignatureOK bool              `json:"signature_ok"`
	CurrentGen  model.Generation  `json:"current_generation"`
	Note        string            `json:"note,omitempty"`
}

// Decision 一次访问的完整决策与审计依据。
type Decision struct {
	Allowed        bool              `json:"allowed"`
	Reason         string            `json:"reason"`
	Degraded       bool              `json:"degraded"`
	Tenant         model.TenantID    `json:"tenant"`
	Resource       model.ResourceID  `json:"resource"`
	Subject        model.PrincipalID `json:"subject"`
	AccessKind     model.AccessKind  `json:"access_kind"`
	EvaluatedAt    int64             `json:"evaluated_at"`
	BanEvidence    *model.BanRecord  `json:"ban_evidence,omitempty"`
	Checks         []Check           `json:"checks"`
	Watermarks     map[string]uint64 `json:"watermarks"`
	IssuerLiveness map[string]string `json:"issuer_liveness"`
}

// EvaluateAny 对证书的所有独立路径逐一核查，任一有效即放行；
// 并按访问类别应用签发者分区语义。所有路径相互独立，单条撤销不牵连其余。
func (e *Engine) EvaluateAny(cert model.AdmissionCertificate, kind model.AccessKind) Decision {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.clock()
	d := Decision{
		Tenant: cert.Tenant, Resource: cert.Resource, Subject: cert.Subject,
		AccessKind: kind, EvaluatedAt: now,
		Watermarks:     map[string]uint64{},
		IssuerLiveness: map[string]string{},
	}

	// 1. 紧急禁用优先于一切。即使证书畸形、是旧签名快照或来自被切换的旧路径，
	//    已收到的禁用都必须生效，且不受压缩/恢复影响（证据常驻 bans）。
	if rec := e.findBan(cert.Tenant, cert.Resource, cert.Subject); rec != nil {
		cp := *rec
		d.BanEvidence = &cp
		d.Allowed, d.Reason = false, model.ReasonDeniedEmergencyBan
		e.recordAudit(d)
		return d
	}

	// 收集证书涉及的全部签发者分区。
	orgSet := map[model.OrgID]bool{}
	for _, path := range cert.Paths {
		for _, edge := range path {
			orgSet[edge.Issuer] = true
		}
	}
	for org := range orgSet {
		d.Watermarks[string(org)] = e.watermarks[org]
		d.IssuerLiveness[string(org)] = e.livenessLocked(org, now)
	}

	// 2. 路径独立核查（无论分区与否都展开，保证拒绝依据完整可核查）。
	d.Checks = e.evaluateAllPathsLocked(cert, now)

	// 3. 分区语义（按访问类别）作用于所有路径核查结果之上。
	if reason := e.partitionGateLocked(orgSet, kind, now); reason != "" {
		d.Allowed, d.Reason = false, reason
		e.recordAudit(d)
		return d
	}

	// 4. 任一路径有效即放行；读若处于宽限期陈旧窗口则标记 degraded。
	for _, c := range d.Checks {
		if c.Valid {
			d.Allowed, d.Reason = true, model.ReasonAllow
			if kind == model.AccessRead {
				d.Degraded = e.degradedReadLocked(orgSet, now)
			}
			e.recordAudit(d)
			return d
		}
	}
	d.Allowed, d.Reason = false, model.ReasonDeniedNoValidPath
	e.recordAudit(d)
	return d
}

// findBan 精确匹配 + 资源级通配（Subject==""）匹配。
func (e *Engine) findBan(t model.TenantID, r model.ResourceID, s model.PrincipalID) *model.BanRecord {
	if rec, ok := e.bans[model.BanKey{Tenant: t, Resource: r, Subject: s}]; ok && !rec.Lifted {
		return rec
	}
	if rec, ok := e.bans[model.BanKey{Tenant: t, Resource: r, Subject: ""}]; ok && !rec.Lifted {
		return rec
	}
	return nil
}

// livenessLocked 返回某签发者当前健康状态：quarantined / unknown / stale / live。
func (e *Engine) livenessLocked(org model.OrgID, now int64) string {
	if e.quarantined[org] {
		return "quarantined"
	}
	if !e.bootstrapped[org] {
		return "unknown"
	}
	hb := e.lastHeartbeat[org]
	if hb == 0 || now-hb > e.readGrace {
		return "stale"
	}
	return "live"
}

// isStaleLocked 判定签发者分区是否处于“不可用/陈旧”状态。
func (e *Engine) isStaleLocked(org model.OrgID, now int64) bool {
	if e.quarantined[org] || !e.bootstrapped[org] {
		return true
	}
	hb := e.lastHeartbeat[org]
	return hb == 0 || now-hb > e.readGrace
}

// partitionGateLocked 实施分区时各类访问的正确语义，返回非空 reason 即拒绝。
//
//   - escalate（特权提升）：任何相关分区陈旧即 fail-closed；
//   - write（写）：同上 fail-closed；
//   - read（读）：仅当超过宽限期仍陈旧才拒绝（grace expired），
//     宽限期内的陈旧读在放行路径上以 degraded 标记，不在这里拒绝。
func (e *Engine) partitionGateLocked(orgs map[model.OrgID]bool, kind model.AccessKind, now int64) string {
	for org := range orgs {
		if !e.isStaleLocked(org, now) {
			continue
		}
		switch kind {
		case model.AccessEscalate, model.AccessWrite:
			return model.ReasonDeniedFailClosed
		case model.AccessRead:
			// 隔离/未引导不属于可容忍的临时分区，直接按隔离拒绝。
			if e.quarantined[org] || !e.bootstrapped[org] {
				return model.ReasonDeniedIssuerQuarantine
			}
			return model.ReasonDeniedReadGraceExpired
		}
	}
	return ""
}

// degradedReadLocked 判定放行的读是否处于“宽限期内陈旧”降级状态。
func (e *Engine) degradedReadLocked(orgs map[model.OrgID]bool, now int64) bool {
	for org := range orgs {
		if e.quarantined[org] || !e.bootstrapped[org] {
			continue
		}
		hb := e.lastHeartbeat[org]
		age := now - hb
		if hb != 0 && age > 0 && age <= e.readGrace {
			return true
		}
	}
	return false
}

// evaluateAllPathsLocked 对每条路径独立核查并返回证据列表。
func (e *Engine) evaluateAllPathsLocked(cert model.AdmissionCertificate, now int64) []Check {
	checks := make([]Check, 0, len(cert.Paths))
	for i, path := range cert.Paths {
		checks = append(checks, e.evaluatePathLocked(i, cert, path, now))
	}
	return checks
}

func (e *Engine) evaluatePathLocked(idx int, cert model.AdmissionCertificate, path []model.DelegationEdge, now int64) Check {
	c := Check{PathIndex: idx}
	if len(path) == 0 {
		c.Valid, c.Reason = false, model.ReasonDeniedEmptyPath
		return c
	}

	// 结构合法性：租户/资源一致、链路首尾相接、终点即证书主体。
	for _, edge := range path {
		c.Issuers = append(c.Issuers, edge.Issuer)
		if edge.Tenant != cert.Tenant || edge.Resource != cert.Resource {
			c.Valid, c.Reason = false, model.ReasonDeniedTenantMismatch
			return c
		}
	}
	for i := range path {
		if i > 0 && path[i].From != path[i-1].To {
			c.Valid, c.Reason = false, model.ReasonDeniedMalformed
			return c
		}
	}
	if path[len(path)-1].To != cert.Subject {
		c.Valid, c.Reason = false, model.ReasonDeniedMalformed
		return c
	}

	// 同一路径内同一签发者代际必须一致，防止混代拼接旧边复活路径。
	seenGen := map[model.OrgID]model.Generation{}
	for _, edge := range path {
		if g, ok := seenGen[edge.Issuer]; ok && g != edge.Generation {
			c.Valid, c.Reason = false, model.ReasonDeniedGenerationStale
			return c
		}
		seenGen[edge.Issuer] = edge.Generation
	}

	// 逐边独立验证：签发者健康、签名/代际、成员退出、有效期。
	for _, edge := range path {
		ev := EdgeEvidence{
			Issuer: edge.Issuer, Generation: edge.Generation,
			From: edge.From, To: edge.To,
		}
		kr := e.keyrings[edge.Issuer]
		if e.quarantined[edge.Issuer] || kr == nil {
			ev.Note = "issuer quarantined or not bootstrapped"
			c.Details = append(c.Details, ev)
			c.Valid, c.Reason = false, model.ReasonDeniedIssuerQuarantine
			return c
		}
		ev.CurrentGen = kr.Current
		if err := kr.VerifyEdge(edge); err != nil {
			ev.SignatureOK = false
			ev.Note = err.Error()
			c.Details = append(c.Details, ev)
			// 区分代际过期与纯签名失败，便于审计定位。
			if edge.Generation != kr.Current {
				c.Valid, c.Reason = false, model.ReasonDeniedGenerationStale
			} else {
				c.Valid, c.Reason = false, model.ReasonDeniedEdgeSignature
			}
			return c
		}
		ev.SignatureOK = true

		// 任一成员退出即撤销整条路径（边的两端都检查）。
		if set := e.exited[edge.Issuer]; set != nil && (set[edge.From] || set[edge.To]) {
			ev.Note = "member has exited"
			c.Details = append(c.Details, ev)
			c.Valid, c.Reason = false, model.ReasonDeniedMemberExited
			return c
		}
		// 有效期（过期路径拒绝）。
		if now < edge.NotBefore || now > edge.NotAfter {
			ev.Note = "edge outside validity window"
			c.Details = append(c.Details, ev)
			c.Valid, c.Reason = false, model.ReasonDeniedPathExpired
			return c
		}
		c.Details = append(c.Details, ev)
	}

	c.Valid, c.Reason = true, model.ReasonAllow
	return c
}

// recordAudit 在审计器存在时追加一条不可变决策记录。
func (e *Engine) recordAudit(d Decision) {
	if e.audit != nil {
		e.audit.Append(d)
	}
}
