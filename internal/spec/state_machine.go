// Package spec 给出协议的小规模参考状态机，并枚举重新授权、换主、过期、
// 压缩、重启等事件的交错顺序。状态机是“规范（spec）”，测试用它对真实
// 引擎的决策做交叉验证：无论事件以何种顺序到达，引擎判定都必须与规范一致。
package spec

import "revauth/internal/model"

// Trigger 作用于单条委派路径的外部触发。
type Trigger string

const (
	TrigReauthorize  Trigger = "reauthorize"  // 重新授权（成员重新加入 + 新边）
	TrigKeyRotation  Trigger = "key_rotation" // 换主/凭证代际换任
	TrigExpire       Trigger = "expire"       // 委派边到达 NotAfter
	TrigMemberExit   Trigger = "member_exit"  // 路径成员退出
	TrigEmergencyBan Trigger = "emergency_ban"
	TrigBanLift      Trigger = "ban_lift"
	TrigCompact      Trigger = "compact" // 压缩（不应改变路径状态）
	TrigRestart      Trigger = "restart" // 重启恢复（不应改变路径状态）
	TrigIssuerFault  Trigger = "issuer_fault"
)

// transition 定义参考状态机的转移表：(当前状态, 触发) -> 下一状态。
//
// 关键不变量：
//   - banned 与 quarantined 为吸收态，只能由显式 BanLift / 故障恢复离开；
//   - revoked（换主/退出导致）不会因 compact、restart 或重放旧证书而回到 active；
//   - compact/restart 对任何状态都是恒等转移（证据持久化的直接体现）。
var transition = map[model.PathState]map[Trigger]model.PathState{
	model.PathActive: {
		TrigReauthorize:  model.PathActive, // 再授权一条同源新边，原 active 路径不变
		TrigKeyRotation:  model.PathRevoked,
		TrigExpire:       model.PathExpired,
		TrigMemberExit:   model.PathRevoked,
		TrigEmergencyBan: model.PathBanned,
		TrigBanLift:      model.PathActive,
		TrigCompact:      model.PathActive,
		TrigRestart:      model.PathActive,
		TrigIssuerFault:  model.PathQuarantined,
	},
	model.PathExpired: {
		TrigReauthorize:  model.PathActive, // 只有重新签发新边才能离开过期态
		TrigKeyRotation:  model.PathRevoked,
		TrigExpire:       model.PathExpired,
		TrigMemberExit:   model.PathRevoked,
		TrigEmergencyBan: model.PathBanned,
		TrigBanLift:      model.PathExpired,
		TrigCompact:      model.PathExpired,
		TrigRestart:      model.PathExpired,
		TrigIssuerFault:  model.PathQuarantined,
	},
	model.PathRevoked: {
		TrigReauthorize:  model.PathActive, // 重新授权（新代际/重新加入）是唯一复活途径
		TrigKeyRotation:  model.PathRevoked,
		TrigExpire:       model.PathRevoked,
		TrigMemberExit:   model.PathRevoked,
		TrigEmergencyBan: model.PathBanned,
		TrigBanLift:      model.PathRevoked,
		TrigCompact:      model.PathRevoked, // 压缩不得清除撤销
		TrigRestart:      model.PathRevoked, // 重启不得借旧数据复活
		TrigIssuerFault:  model.PathQuarantined,
	},
	model.PathBanned: {
		TrigReauthorize:  model.PathBanned, // 禁用期内重授权无效
		TrigKeyRotation:  model.PathBanned,
		TrigExpire:       model.PathBanned,
		TrigMemberExit:   model.PathBanned,
		TrigEmergencyBan: model.PathBanned,
		TrigBanLift:      model.PathActive, // 仅显式解除可离开
		TrigCompact:      model.PathBanned, // 粘性：压缩不得清除禁用
		TrigRestart:      model.PathBanned, // 粘性：重启/恢复不得清除禁用
		TrigIssuerFault:  model.PathQuarantined,
	},
	model.PathQuarantined: {
		TrigReauthorize:  model.PathQuarantined,
		TrigKeyRotation:  model.PathQuarantined,
		TrigExpire:       model.PathQuarantined,
		TrigMemberExit:   model.PathQuarantined,
		// 隔离分区不可写入：禁用事件无法落库，状态保持隔离（与引擎跳过一致）。
		TrigEmergencyBan: model.PathQuarantined,
		TrigBanLift:      model.PathQuarantined,
		TrigCompact:      model.PathQuarantined,
		TrigRestart:      model.PathQuarantined,
		TrigIssuerFault:  model.PathQuarantined,
	},
}

// PathFSM 单条委派路径的参考状态机。
type PathFSM struct {
	State model.PathState
}

// NewPathFSM 从 active 开始。
func NewPathFSM() *PathFSM { return &PathFSM{State: model.PathActive} }

// Step 施加一个触发，返回新状态。未知转移保持原状态并返回 ok=false。
func (f *PathFSM) Step(t Trigger) (model.PathState, bool) {
	next, ok := transition[f.State][t]
	if !ok {
		return f.State, false
	}
	f.State = next
	return next, true
}

// ReachableFrom 枚举从某状态出发、施加给定触发序列（保序）能到达的状态，
// 用于测试生成期望结果。
func ReachableFrom(start model.PathState, triggers []Trigger) model.PathState {
	f := &PathFSM{State: start}
	for _, t := range triggers {
		if _, ok := f.Step(t); !ok {
			break
		}
	}
	return f.State
}
