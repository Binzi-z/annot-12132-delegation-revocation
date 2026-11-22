package eventlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"revauth/internal/model"
)

// ErrNoSnapshot 尚无快照。
var ErrNoSnapshot = errors.New("eventlog: no snapshot")

// PubKeyEntry 快照中的代际公钥条目。
type PubKeyEntry struct {
	Generation model.Generation `json:"generation"`
	PublicKey  []byte           `json:"public_key"`
}

// Snapshot 压缩快照：节点重建全部判定能力所需的“最少状态”。
//
// 明确不保存任何完整历史，只保存：
//   - 每个签发者当前代际与全部代际公钥（当前代际用于准入，旧代际仅用于审计）；
//   - 已退出主体集合（撤销证据）；
//   - 全部仍生效或已显式解除的紧急禁用（粘性证据，绝不丢弃）；
//   - 每个签发者的可迁移水位；
//   - 每个签发者最近心跳时间（分区判定）。
type Snapshot struct {
	Version       int                                    `json:"version"`
	TakenAt       int64                                  `json:"taken_at"`
	CurrentGen    map[string]model.Generation            `json:"current_generation"`
	PubKeys       map[string][]PubKeyEntry               `json:"public_keys"`
	ExitedMembers map[string][]model.PrincipalID         `json:"exited_members"`
	Bans          []model.BanRecord                      `json:"bans"`
	Watermarks    map[string]uint64                      `json:"watermarks"`
	LastHeartbeat map[string]int64                       `json:"last_heartbeat"`
	LogHeads      map[string]string                      `json:"log_heads"`
}

// Hash 计算快照内容摘要，写入 EvSnapshotMarker 以绑定快照与后续链。
func (s *Snapshot) Hash() string {
	sum := sha256.Sum256(model.CanonicalJSON(s))
	return hex.EncodeToString(sum[:])
}

func snapshotPath(root string) string {
	return filepath.Join(root, "snapshot.json")
}

// SaveSnapshot 原子写入快照（临时文件 + rename + fsync 目录）。
func SaveSnapshot(root string, s *Snapshot) error {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	tmp := snapshotPath(root) + ".tmp"
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, snapshotPath(root)); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// LoadSnapshot 读取最近快照；不存在返回 ErrNoSnapshot。
func LoadSnapshot(root string) (*Snapshot, error) {
	b, err := os.ReadFile(snapshotPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNoSnapshot
		}
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
