package model

import "encoding/json"

// canonical 返回确定性 JSON 字节。
// Go 的 encoding/json 对结构体按字段声明序、对 map 按键排序输出，
// 因此同一逻辑对象在任意进程中得到相同字节，可用于哈希链与签名。
func canonical(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// 仅用于协议内已知结构；出现不可编码类型属于编程错误。
		panic("revauth: canonical encode failed: " + err.Error())
	}
	return b
}

// CanonicalJSON 导出确定性编码，供其他包（签名、快照摘要）复用。
func CanonicalJSON(v any) []byte {
	return canonical(v)
}
