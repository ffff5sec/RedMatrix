// plugin_register.go PR-S49/S56 —— plugin 注册按 env 切换 + 多选聚合。
//
// PR-S49：引入 env 让 ops 选实现，但 Registry 仍 kind→Plugin 1:1。
// PR-S56：Registry.Register 自动聚合到 group；env 改逗号分隔多选语义。
//
// SUBDOMAIN_PLUGIN=subfinder         → 仅 subfinder
// SUBDOMAIN_PLUGIN=subfinder,amass   → 两个并跑结果合并
// SUBDOMAIN_PLUGIN=crtsh,fofa,hunter → 3 个 L1 一起跑
//
// 任一 plugin 构造失败（如 binary 缺 / env 缺 key）→ 跳过该项继续下一个；
// 全部 plugin 失败 → fallback mock（由 RegisterAllMock 兜底，Run 时 group
// 解空后 Get 返 mock）。
package main

import (
	"os"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/amass"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/crtsh"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/fingerprintx"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/fofa"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/gospider"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/httpx"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/hunter"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/katana"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/ksubdomain"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/nmap"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/quake"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/rustscan"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/subfinder"
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin/wayback"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// pluginFactory 把"名字 → New()"包成统一签名，供 register loop 调用。
type pluginFactory func() (plugin.Plugin, error)

// parseChoices 解析 env 值：逗号分 + 小写 + 去空 + 去重；空 / 未设返 [default]。
// 例：" Subfinder, , AMASS "  →  ["subfinder", "amass"]
func parseChoices(envKey, def string) []string {
	raw := strings.TrimSpace(os.Getenv(envKey))
	if raw == "" {
		return []string{def}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		s := strings.ToLower(strings.TrimSpace(part))
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{def}
	}
	return out
}

// registerChoices 通用 register loop：按 choices 顺序构造 + 注册；
// 构造失败 log 但不阻塞下一个。返实际成功注册的数量（供日志 / 测试用）。
func registerChoices(
	registry *plugin.Registry,
	logger *log.Logger,
	kind string,
	choices []string,
	factories map[string]pluginFactory,
) int {
	registered := 0
	for _, name := range choices {
		fac, ok := factories[name]
		if !ok {
			logger.Info("plugin choice not recognized; ignored",
				"kind", kind, "choice", name)
			continue
		}
		p, err := fac()
		if err != nil {
			logger.Info("plugin init failed; skipped",
				"kind", kind, "impl", name, "err", err.Error())
			continue
		}
		registry.Register(p)
		registered++
		logger.Info("plugin registered", "kind", kind, "impl", name)
	}
	return registered
}

// registerPortScanPlugin 按 PORT_SCAN_PLUGIN env 注册（多选用逗号分）。
// 支持："nmap"（default）/ "rustscan"。多选聚合到 group。
func registerPortScanPlugin(registry *plugin.Registry, logger *log.Logger) {
	choices := parseChoices("PORT_SCAN_PLUGIN", "nmap")
	registerChoices(registry, logger, "port_scan", choices, map[string]pluginFactory{
		"nmap":     func() (plugin.Plugin, error) { return nmap.New() },
		"rustscan": func() (plugin.Plugin, error) { return rustscan.New() },
	})
}

// registerSubdomainPlugin 按 SUBDOMAIN_PLUGIN env 注册（多选用逗号分）。
// 支持：
//   - "subfinder"（default，L2 被动情报源聚合）
//   - "amass"（L2 被动 + 主动 DNS 推导）
//   - "ksubdomain"（L2 字典爆破）
//   - "crtsh"（L1 适配器，CT 日志 API，无 key）
//   - "fofa"（L1 适配器，需 env FOFA_EMAIL + FOFA_KEY）
//   - "hunter"（L1 适配器，需 env HUNTER_KEY）
//   - "quake"（L1 适配器，需 env QUAKE_KEY）
//
// 多选示例：SUBDOMAIN_PLUGIN=subfinder,crtsh,fofa → 3 个并跑结果合并。
func registerSubdomainPlugin(registry *plugin.Registry, logger *log.Logger) {
	choices := parseChoices("SUBDOMAIN_PLUGIN", "subfinder")
	registerChoices(registry, logger, "subdomain", choices, map[string]pluginFactory{
		"subfinder":  func() (plugin.Plugin, error) { return subfinder.New() },
		"amass":      func() (plugin.Plugin, error) { return amass.New() },
		"ksubdomain": func() (plugin.Plugin, error) { return ksubdomain.New() },
		"crtsh":      func() (plugin.Plugin, error) { return crtsh.New() },
		"fofa":       func() (plugin.Plugin, error) { return fofa.New() },
		"hunter":     func() (plugin.Plugin, error) { return hunter.New() },
		"quake":      func() (plugin.Plugin, error) { return quake.New() },
	})
}

// registerFingerprintPlugin 按 FINGERPRINT_PLUGIN env 注册。
// 支持："httpx"（default，仅 HTTP/HTTPS）/ "fingerprintx"（30+ TCP/UDP 服务）。
// 多选示例：FINGERPRINT_PLUGIN=httpx,fingerprintx → Web + 非 Web 服务并跑。
func registerFingerprintPlugin(registry *plugin.Registry, logger *log.Logger) {
	choices := parseChoices("FINGERPRINT_PLUGIN", "httpx")
	registerChoices(registry, logger, "fingerprint", choices, map[string]pluginFactory{
		"httpx":        func() (plugin.Plugin, error) { return httpx.NewFingerprint() },
		"fingerprintx": func() (plugin.Plugin, error) { return fingerprintx.New() },
	})
}

// registerWebCrawlPlugin 按 WEB_CRAWL_PLUGIN env 注册。
// 支持："httpx"（default）/ "katana" / "gospider" / "wayback"。
// 多选示例：WEB_CRAWL_PLUGIN=katana,wayback → 主动爬 + 被动归档并跑。
func registerWebCrawlPlugin(registry *plugin.Registry, logger *log.Logger) {
	choices := parseChoices("WEB_CRAWL_PLUGIN", "httpx")
	registerChoices(registry, logger, "web_crawl", choices, map[string]pluginFactory{
		"httpx":    func() (plugin.Plugin, error) { return httpx.NewWebCrawl() },
		"katana":   func() (plugin.Plugin, error) { return katana.New() },
		"gospider": func() (plugin.Plugin, error) { return gospider.New() },
		"wayback":  func() (plugin.Plugin, error) { return wayback.New() },
	})
}
