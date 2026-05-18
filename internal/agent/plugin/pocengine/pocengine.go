// Package pocengine 是 vuln_scan 任务的 L3 真插件（PR-S69，SPEC §2.4）。
//
// 跟 nuclei (L2) 互补：
//   - nuclei 依赖外部二进制 + nuclei-templates 仓库（每节点单独维护）
//   - pocengine 内嵌 RedMatrix POC 引擎（internal/poc）+ 内嵌默认模板 +
//     可选 env REDMATRIX_POC_TEMPLATE_DIR 加载自定义模板
//
// Registry kind=vuln_scan 多源聚合（PR-S56 group）：nuclei + pocengine 并跑
// 结果合并。
package pocengine

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/safetarget"
	"github.com/ffff5sec/RedMatrix/internal/poc"
)

// envTemplateDir 外置模板目录 env 名。可空 = 仅用内嵌。
const envTemplateDir = "REDMATRIX_POC_TEMPLATE_DIR"

// Plugin pocengine 插件。
type Plugin struct {
	engine    *poc.Engine
	templates []*poc.Template
}

// New 构造：加载内嵌默认模板 + 可选 env 外置目录。
// 内嵌加载失败（不应该，CI 兜底）= 返 ErrNotInstalled 让 caller 回落 mock。
func New() (*Plugin, error) {
	defaults, err := poc.LoadDefault()
	if err != nil {
		return nil, plugin.ErrNotInstalled
	}
	all := append([]*poc.Template{}, defaults...)
	if dir := strings.TrimSpace(os.Getenv(envTemplateDir)); dir != "" {
		extras, err := poc.LoadDir(os.DirFS(dir), ".", nil)
		if err == nil {
			all = append(all, extras...)
		}
	}
	return &Plugin{engine: poc.NewEngine(nil), templates: all}, nil
}

// NewWithFS 测试用：从给定 fs.FS 加载模板。
func NewWithFS(fsys fs.FS, root string) (*Plugin, error) {
	tpls, err := poc.LoadDir(fsys, root, nil)
	if err != nil {
		return nil, err
	}
	if len(tpls) == 0 {
		return nil, errors.New("pocengine: no templates loaded")
	}
	return &Plugin{engine: poc.NewEngine(nil), templates: tpls}, nil
}

// Kind 实现 Plugin。
func (*Plugin) Kind() string { return "vuln_scan" }

// IsMock 实现 Plugin；真插件 false。
func (*Plugin) IsMock() bool { return false }

// Templates 已加载的模板（测试 / 调试用）。
func (p *Plugin) Templates() []*poc.Template { return p.templates }

// Run 实现 Plugin。
//
// target_kind:
//   - url：直接当 BaseURL 跑
//   - host / ip：自动补 http:// 当 BaseURL
//   - cidr：拒（vuln_scan 走具体 url/host）
//
// settings 暂未使用（保留 future：severity 过滤、tag 选择）。
func (p *Plugin) Run(
	ctx context.Context,
	target, targetKind string,
	_ map[string]any,
) ([]map[string]any, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, errors.New("pocengine: empty target")
	}
	switch strings.ToLower(targetKind) {
	case "cidr":
		return nil, errors.New("pocengine: target_kind=cidr 不支持（先用 nmap / fingerprint 拆成 host / url）")
	}
	if err := safetarget.ValidateTarget(target, targetKind); err != nil {
		return nil, err
	}
	baseURL := target
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	findings := p.engine.Run(ctx, baseURL, p.templates)
	return findingsToResults(findings, target), nil
}

// findingsToResults 转 finding 为 result 行（与 nuclei plugin 输出 schema 对齐）。
// 字段：
//
//	template_id   string
//	host          string  (caller 传入的 target)
//	info: {name, severity, tags, reference}
//	engine        "redmatrix-poc"   —— 与 nuclei 区分
func findingsToResults(findings []*poc.Finding, target string) []map[string]any {
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		out = append(out, map[string]any{
			"template_id": f.TemplateID,
			"host":        target,
			"engine":      "redmatrix-poc",
			"info": map[string]any{
				"name":      f.Name,
				"severity":  string(f.Severity),
				"tags":      f.Tags,
				"reference": f.Reference,
			},
		})
	}
	return out
}
