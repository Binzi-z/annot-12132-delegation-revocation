package model

import (
	"crypto/sha256"
	"encoding/hex"
)

// EventKind 持久化事件类型。事件按签发者分区，各自独立成链。
type EventKind string

const (
	// EvKeyRotated 换主/凭证代际换任。携带新代际公钥，旧代际立即失效。
	EvKeyRotated EventKind = "key_rotated"
	// EvMemberExited 主体退出。凡包含该主体的委派路径全部撤销。
	EvMemberExited EventKind = "member_exited"
	// EvMemberRejoined 主体重新加入并获得新凭证（重新授权的前置条件）。
	EvMemberRejoined EventKind = "member_rejoined"
	// EvEmergencyBan 紧急禁用。粘性证据，压缩/快照/换链均不得清除。
	EvEmergencyBan EventKind = "emergency_ban"
	// EvBanLifted 显式解除紧急禁用（唯一合法解除途径）。
	EvBanLifted EventKind = "ban_lifted"
	// EvHeartbeat 签发者心跳，用于分区判定（freshness 水位）。
	EvHeartbeat EventKind = "heartbeat"
	// EvSnapshotMarker 压缩分界标记：此前事件已进入快照。
	EvSnapshotMarker EventKind = "snapshot_marker"
)

// KeyRotatedPayload 换主事件载荷。
type KeyRotatedPayload struct {
	NewGeneration Generation `json:"new_generation"`
	PublicKey     []byte     `json:"public_key"` // Ed25519 公钥
	Reason        string     `json:"reason,omitempty"`
}

// MemberExitedPayload 主体退出事件载荷。
type MemberExitedPayload struct {
	Member PrincipalID `json:"member"`
	Reason string      `json:"reason,omitempty"`
}

// MemberRejoinedPayload 主体重新加入事件载荷。
type MemberRejoinedPayload struct {
	Member PrincipalID `json:"member"`
}

// EmergencyBanPayload 紧急禁用载荷；Subject 为空表示资源级禁用。
type EmergencyBanPayload struct {
	Tenant   TenantID    `json:"tenant"`
	Resource ResourceID  `json:"resource"`
	Subject  PrincipalID `json:"subject,omitempty"`
	Reason   string      `json:"reason,omitempty"`
}

// BanLiftedPayload 解除禁用载荷，必须与既有禁用维度完全一致。
type BanLiftedPayload struct {
	Tenant   TenantID    `json:"tenant"`
	Resource ResourceID  `json:"resource"`
	Subject  PrincipalID `json:"subject,omitempty"`
}

// HeartbeatPayload 心跳载荷。
type HeartbeatPayload struct {
	Nonce []byte `json:"nonce,omitempty"`
}

// SnapshotMarkerPayload 压缩分界载荷，记录快照内容摘要。
type SnapshotMarkerPayload struct {
	SnapshotHash string `json:"snapshot_hash"`
}

// Event 持久化事件信封。
//
// 每个签发者一条独立哈希链：Seq 在该签发者分区内从 1 连续递增，
// PrevHash 指向前一事件的 Hash，使任何丢失、重排、篡改都可被独立检测，
// 且一个签发者的链损坏不会牵连另一个签发者（故障隔离）。
type Event struct {
	Seq      uint64          `json:"seq"`
	Issuer   OrgID           `json:"issuer"`
	Kind     EventKind       `json:"kind"`
	EmittedAt int64          `json:"emitted_at"`
	Payload  any             `json:"payload"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
}

// Digest 返回事件内容摘要（不含 Hash 字段本身），用于哈希链与签名校验。
func (e Event) Digest() string {
	core := struct {
		Seq       uint64    `json:"seq"`
		Issuer    OrgID     `json:"issuer"`
		Kind      EventKind `json:"kind"`
		EmittedAt int64     `json:"emitted_at"`
		Payload   any       `json:"payload"`
		PrevHash  string    `json:"prev_hash"`
	}{e.Seq, e.Issuer, e.Kind, e.EmittedAt, e.Payload, e.PrevHash}
	sum := sha256.Sum256(canonical(core))
	return hex.EncodeToString(sum[:])
}
