package model_test

import (
	"encoding/json"
	"testing"

	"revauth/internal/model"
)

// TestEventPayloadRoundTrip 事件经 JSON 持久化后，载荷必须还原为具体强类型，
// 否则引擎的类型断言会失败。覆盖全部事件种类。
func TestEventPayloadRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		kind model.EventKind
		payload any
		want  any
	}{
		{"key_rotated", model.EvKeyRotated,
			model.KeyRotatedPayload{NewGeneration: 2, PublicKey: []byte{1, 2, 3}},
			model.KeyRotatedPayload{}},
		{"member_exited", model.EvMemberExited,
			model.MemberExitedPayload{Member: "alice"}, model.MemberExitedPayload{}},
		{"member_rejoined", model.EvMemberRejoined,
			model.MemberRejoinedPayload{Member: "alice"}, model.MemberRejoinedPayload{}},
		{"emergency_ban", model.EvEmergencyBan,
			model.EmergencyBanPayload{Tenant: "t", Resource: "r", Subject: "s"},
			model.EmergencyBanPayload{}},
		{"ban_lift", model.EvBanLift,
			model.BanLiftedPayload{Tenant: "t", Resource: "r"}, model.BanLiftedPayload{}},
		{"heartbeat", model.EvHeartbeat,
			model.HeartbeatPayload{Nonce: []byte("n")}, model.HeartbeatPayload{}},
		{"snapshot_marker", model.EvSnapshotMarker,
			model.SnapshotMarkerPayload{SnapshotHash: "abc"}, model.SnapshotMarkerPayload{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := model.Event{Seq: 1, Issuer: "org-a", Kind: tc.kind, Payload: tc.payload}
			ev.Hash = ev.Digest()
			b, err := json.Marshal(ev)
			if err != nil {
				t.Fatal(err)
			}
			var got model.Event
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if got.Hash != ev.Hash {
				t.Fatal("hash changed across roundtrip")
			}
			if got.Payload == nil {
				t.Fatal("payload decoded to nil")
			}
			if typeName(got.Payload) != typeName(tc.want) {
				t.Fatalf("payload type = %T, want %T", got.Payload, tc.want)
			}
		})
	}
}

func typeName(v any) string {
	switch v.(type) {
	case model.KeyRotatedPayload:
		return "KeyRotatedPayload"
	case model.MemberExitedPayload:
		return "MemberExitedPayload"
	case model.MemberRejoinedPayload:
		return "MemberRejoinedPayload"
	case model.EmergencyBanPayload:
		return "EmergencyBanPayload"
	case model.BanLiftedPayload:
		return "BanLiftedPayload"
	case model.HeartbeatPayload:
		return "HeartbeatPayload"
	case model.SnapshotMarkerPayload:
		return "SnapshotMarkerPayload"
	default:
		return "unknown"
	}
}
