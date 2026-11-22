package model

import "encoding/json"

// rawEvent 用于自定义反序列化：先解出信封字段，再按 Kind 还原具体载荷类型。
type rawEvent struct {
	Seq       uint64          `json:"seq"`
	Issuer    OrgID           `json:"issuer"`
	Kind      EventKind       `json:"kind"`
	EmittedAt int64           `json:"emitted_at"`
	Payload   json.RawMessage `json:"payload"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// UnmarshalJSON 保证 Payload 被还原为具体的强类型结构，
// 而不是 encoding/json 默认的 map[string]any，使引擎的类型断言可用。
func (e *Event) UnmarshalJSON(b []byte) error {
	var r rawEvent
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	var payload any
	if len(r.Payload) > 0 {
		p, err := decodePayload(r.Kind, r.Payload)
		if err != nil {
			return err
		}
		payload = p
	}
	*e = Event{
		Seq: r.Seq, Issuer: r.Issuer, Kind: r.Kind, EmittedAt: r.EmittedAt,
		Payload: payload, PrevHash: r.PrevHash, Hash: r.Hash,
	}
	return nil
}

func decodePayload(kind EventKind, raw json.RawMessage) (any, error) {
	var p any
	switch kind {
	case EvKeyRotated:
		v := KeyRotatedPayload{}
		p = &v
	case EvMemberExited:
		v := MemberExitedPayload{}
		p = &v
	case EvMemberRejoined:
		v := MemberRejoinedPayload{}
		p = &v
	case EvEmergencyBan:
		v := EmergencyBanPayload{}
		p = &v
	case EvBanLifted:
		v := BanLiftedPayload{}
		p = &v
	case EvHeartbeat:
		v := HeartbeatPayload{}
		p = &v
	case EvSnapshotMarker:
		v := SnapshotMarkerPayload{}
		p = &v
	default:
		// 未知类型保留原始 JSON，不阻断其他签发者分区的处理。
		return json.RawMessage(append([]byte(nil), raw...)), nil
	}
	if err := json.Unmarshal(raw, p); err != nil {
		return nil, err
	}
	// 解引用为值类型，与 Emit 路径保持一致。
	return derefPayload(p), nil
}

func derefPayload(p any) any {
	switch v := p.(type) {
	case *KeyRotatedPayload:
		return *v
	case *MemberExitedPayload:
		return *v
	case *MemberRejoinedPayload:
		return *v
	case *EmergencyBanPayload:
		return *v
	case *BanLiftedPayload:
		return *v
	case *HeartbeatPayload:
		return *v
	case *SnapshotMarkerPayload:
		return *v
	default:
		return p
	}
}
