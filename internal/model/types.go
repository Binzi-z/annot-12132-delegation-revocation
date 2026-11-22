// Package model 定义双组织授权回收协议的核心数据结构。
//
// 设计要点：
//   - 主体、组织、资源、租户均使用稳定的字符串标识；
//   - 委派边（DelegationEdge）由各签发者独立签名，证书本身不要求签名，
//     因为证书的可信性完全来自“每条边可被对应代际公钥独立验证”；
//   - 所有结构均使用确定性 JSON 编码（见 crypto.CanonicalJSON），便于跨节点复核。
package model

// PrincipalID 主体标识（用户、服务账号等）。
type PrincipalID string

// OrgID 组织/签发者分区标识。协议中固定存在两个组织。
type OrgID string

// TenantID 租户标识。所有访问判定都显式携带租户上下文。
type TenantID string

// ResourceID 资源标识，资源在租户内唯一。
type ResourceID string

// Generation 凭证代际。换主/轮换单调递增；代际不匹配即撤销旧路径。
type Generation uint64

// AccessKind 访问类别，决定分区时的判定语义。
type AccessKind string

const (
	// AccessRead 只读访问。分区宽限期内可降级放行（degraded）。
	AccessRead AccessKind = "read"
	// AccessWrite 写访问。分区即拒绝（fail-closed）。
	AccessWrite AccessKind = "write"
	// AccessEscalate 特权提升/管理操作。任何时刻都 fail-closed。
	AccessEscalate AccessKind = "escalate"
)

// 决策原因码：每次访问决策的可核查依据（Decision.Reason）。
const (
	ReasonAllow                 = "allow"
	ReasonDeniedMalformed       = "denied_malformed_certificate"
	ReasonDeniedEmptyPath       = "denied_empty_delegation_path"
	ReasonDeniedTenantMismatch  = "denied_tenant_mismatch"
	ReasonDeniedEdgeSignature   = "denied_edge_signature_invalid"
	ReasonDeniedGenerationStale = "denied_generation_stale"
	ReasonDeniedMemberExited    = "denied_member_exited"
	ReasonDeniedPathExpired     = "denied_path_expired"
	ReasonDeniedEmergencyBan    = "denied_emergency_ban"
	ReasonDeniedIssuerQuarantine = "denied_issuer_quarantine"
	ReasonDeniedReadGraceExpired = "denied_partition_read_grace_expired"
	ReasonDeniedFailClosed      = "denied_partition_fail_closed"
	ReasonDeniedNoValidPath     = "denied_no_valid_path"
)

// DelegationEdge 委派链上的一条有向边：From 向 To 委派对资源的访问。
// 跨组织链允许相邻边的 Issuer 不同；同一条链内同一签发者的代际必须一致。
type DelegationEdge struct {
	Tenant     TenantID     `json:"tenant"`
	Resource   ResourceID   `json:"resource"`
	Issuer     OrgID        `json:"issuer"`     // 对该边签名的签发者
	Generation Generation   `json:"generation"` // 签发时签发者凭证代际
	From       PrincipalID  `json:"from"`
	To         PrincipalID  `json:"to"`
	NotBefore  int64        `json:"not_before"` // Unix 秒
	NotAfter   int64        `json:"not_after"`  // Unix 秒
	Sig        []byte       `json:"sig"`        // Issuer 当前代际私钥对规范编码的签名
}

// AdmissionCertificate 可独立验证的准入证书。
//
// 独立验证含义：拿到证书 + 各签发者当前公钥/代际与撤销证据，无需回溯历史日志
// 即可判定每一条候选路径是否有效。证书可同时携带多条互不相关的委派链，
// 一条被撤销不影响其他独立路径。
type AdmissionCertificate struct {
	Tenant   TenantID         `json:"tenant"`
	Resource ResourceID       `json:"resource"`
	Subject  PrincipalID      `json:"subject"` // 最终访问者，必须是每条路径的终点
	IssuedAt int64            `json:"issued_at"`
	Paths    [][]DelegationEdge `json:"paths"`
}

// BanKey 紧急禁用证据的最小键。Subject 为空字符串表示资源级通配禁用。
type BanKey struct {
	Tenant   TenantID
	Resource ResourceID
	Subject  PrincipalID
}

// BanRecord 已收到的紧急禁用。该证据永不被压缩/快照/换链清除，
// 只能由同维度的 BanLifted 显式解除。
type BanRecord struct {
	Tenant     TenantID    `json:"tenant"`
	Resource   ResourceID  `json:"resource"`
	Subject    PrincipalID `json:"subject,omitempty"`
	IssuedBy   OrgID       `json:"issued_by"`
	BannedAt   int64       `json:"banned_at"`
	Reason     string      `json:"reason"`
	Lifted     bool        `json:"lifted"`
	LiftedAt   int64       `json:"lifted_at,omitempty"`
	LiftedBy   OrgID       `json:"lifted_by,omitempty"`
}

// GenKey 代际密钥映射键。
type GenKey struct {
	Issuer OrgID
	Gen    Generation
}

// PathState 参考状态机中单条委派路径的状态。
type PathState string

const (
	PathActive      PathState = "active"
	PathExpired     PathState = "expired"
	PathRevoked     PathState = "revoked"
	PathBanned      PathState = "banned"
	PathQuarantined PathState = "quarantined"
)
