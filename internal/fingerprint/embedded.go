package fingerprint

import _ "embed"

//go:embed rules.yaml
var defaultRulesYAML []byte

// Default 返回内嵌默认规则集构造的 Library。
// 内嵌 yaml 解析失败会 panic（boot 必然失败，应被 go test 兜底捕获）。
func Default() *Library {
	lib, err := NewLibrary(defaultRulesYAML)
	if err != nil {
		panic("fingerprint: default rules.yaml invalid: " + err.Error())
	}
	return lib
}
