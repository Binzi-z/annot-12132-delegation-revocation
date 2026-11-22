package spec

import (
	"sort"
)

// Interleaving 一组事件触发的一个具体交错顺序。
type Interleaving struct {
	Name     string
	Triggers []Trigger
}

// permutations 返回输入切片的全部唯一排列（去重相邻等价项）。
func permutations(in []Trigger) [][]Trigger {
	var out [][]Trigger
	used := make([]bool, len(in))
	var rec func(cur []Trigger)
	seen := map[string]bool{}
	rec = func(cur []Trigger) {
		if len(cur) == len(in) {
			cp := append([]Trigger(nil), cur...)
			key := keyOf(cp)
			if !seen[key] {
				seen[key] = true
				out = append(out, cp)
			}
			return
		}
		for i := range in {
			if used[i] {
				continue
			}
			used[i] = true
			rec(append(cur, in[i]))
			used[i] = false
		}
	}
	rec(nil)
	return out
}

func keyOf(ts []Trigger) string {
	s := ""
	for _, t := range ts {
		s += string(t) + "|"
	}
	return s
}

// Enumerate 枚举协议要求覆盖的交错集合：
//
//  1. 核心五事件（重新授权、换主、过期、压缩、重启）的全部排列；
//  2. 围绕紧急禁用的粘性交错（禁用先于/后于压缩、重启、换链）；
//  3. 退出与重新授权的先后交错；
//  4. 签发者故障与恢复交错。
//
// 返回的每个交错都可驱动真实引擎，并用 PathFSM 的期望状态交叉验证。
func Enumerate() []Interleaving {
	var res []Interleaving

	core := []Trigger{TrigReauthorize, TrigKeyRotation, TrigExpire, TrigCompact, TrigRestart}
	for i, p := range permutations(core) {
		res = append(res, Interleaving{
			Name:     "core_permutation_" + itoa(i),
			Triggers: p,
		})
	}

	// 粘性禁用：禁用与压缩/重启/换主/换链的所有相对顺序。
	banGroup := []Trigger{TrigEmergencyBan, TrigCompact, TrigRestart, TrigKeyRotation, TrigBanLift}
	for i, p := range permutations(banGroup) {
		res = append(res, Interleaving{
			Name:     "ban_sticky_" + itoa(i),
			Triggers: p,
		})
	}

	// 退出 / 再授权 / 过期交错。
	exitGroup := []Trigger{TrigMemberExit, TrigReauthorize, TrigExpire, TrigCompact, TrigRestart}
	for i, p := range permutations(exitGroup) {
		res = append(res, Interleaving{
			Name:     "exit_reauth_" + itoa(i),
			Triggers: p,
		})
	}

	// 故障隔离交错。
	faultGroup := []Trigger{TrigIssuerFault, TrigRestart, TrigCompact, TrigEmergencyBan, TrigBanLift}
	for i, p := range permutations(faultGroup) {
		res = append(res, Interleaving{
			Name:     "fault_" + itoa(i),
			Triggers: p,
		})
	}

	sort.SliceStable(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
