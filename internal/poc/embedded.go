package poc

import "embed"

//go:embed templates
var defaultTemplatesFS embed.FS

// DefaultTemplatesFS 返内嵌的默认模板目录 FS。
// 调用方：lib, _ := poc.LoadDir(poc.DefaultTemplatesFS(), "templates", nil)
func DefaultTemplatesFS() embed.FS { return defaultTemplatesFS }

// DefaultTemplatesRoot 内嵌 FS 中模板根目录。
const DefaultTemplatesRoot = "templates"

// LoadDefault 加载所有内嵌模板。任意单个失败仅静默跳过（onError = nil）。
func LoadDefault() ([]*Template, error) {
	return LoadDir(defaultTemplatesFS, DefaultTemplatesRoot, nil)
}
