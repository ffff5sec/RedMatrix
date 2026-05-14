// plugin_register.go PR-S49 —— plugin 注册按 env 切换实现。
//
// 引入背景：SPEC §2.5 资产发现矩阵列出多个工具（nmap / rustscan / subfinder /
// amass / httpx / katana），但 plugin.Registry 当前是 kind → Plugin 1:1 映射。
// 引入 env 让 ops 自主选实现，不改架构。
//
// 后续 PR-S5x 计划改 Registry 为 kind → []Plugin 聚合多源，env 转为白名单。
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

// envOrDefault 读 env 并归一为小写；空 / 未设返 def。
func envOrDefault(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return strings.ToLower(v)
}

// registerPortScanPlugin 按 PORT_SCAN_PLUGIN env 注册 port_scan 真插件。
// 支持值："nmap"（default）/ "rustscan"。未识别 → 用 default。
// 真工具未安装 → 静默回落 mock（已由 RegisterAllMock 兜底）。
func registerPortScanPlugin(registry *plugin.Registry, logger *log.Logger) {
	choice := envOrDefault("PORT_SCAN_PLUGIN", "nmap")
	if choice == "rustscan" {
		p, err := rustscan.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "port_scan", "impl", "rustscan")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "port_scan", "tool", "rustscan", "err", err.Error())
		return
	}
	// nmap 或未识别值
	p, err := nmap.New()
	if err == nil {
		registry.Register(p)
		logger.Info("plugin registered", "kind", "port_scan", "impl", "nmap")
		return
	}
	logger.Info("plugin not installed; falling back to mock",
		"kind", "port_scan", "tool", "nmap", "err", err.Error())
}

// registerSubdomainPlugin 按 SUBDOMAIN_PLUGIN env 注册 subdomain 真插件。
// 支持值：
//   - "subfinder"（default，L2 被动情报源聚合）
//   - "amass"（L2 被动 + 主动 DNS 推导）
//   - "ksubdomain"（L2 字典爆破）
//   - "crtsh"（L1 适配器，CT 日志 API）
//   - "fofa"（L1 适配器，需 env FOFA_EMAIL + FOFA_KEY）
//   - "hunter"（L1 适配器，需 env HUNTER_KEY）
//   - "quake"（L1 适配器，需 env QUAKE_KEY）
func registerSubdomainPlugin(registry *plugin.Registry, logger *log.Logger) {
	choice := envOrDefault("SUBDOMAIN_PLUGIN", "subfinder")
	switch choice {
	case "amass":
		p, err := amass.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "amass")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "subdomain", "tool", "amass", "err", err.Error())
		return
	case "ksubdomain":
		p, err := ksubdomain.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "ksubdomain")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "subdomain", "tool", "ksubdomain", "err", err.Error())
		return
	case "crtsh":
		// L1 适配器：HTTP API，无 binary 依赖，几乎不会 fail
		p, err := crtsh.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "crtsh", "layer", "L1")
			return
		}
		logger.Info("L1 adapter init failed; falling back to mock",
			"kind", "subdomain", "tool", "crtsh", "err", err.Error())
		return
	case "fofa":
		// L1 适配器：需 env FOFA_EMAIL + FOFA_KEY
		p, err := fofa.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "fofa", "layer", "L1")
			return
		}
		logger.Info("L1 adapter init failed (env FOFA_EMAIL + FOFA_KEY required); falling back to mock",
			"kind", "subdomain", "tool", "fofa", "err", err.Error())
		return
	case "hunter":
		// L1 适配器：需 env HUNTER_KEY
		p, err := hunter.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "hunter", "layer", "L1")
			return
		}
		logger.Info("L1 adapter init failed (env HUNTER_KEY required); falling back to mock",
			"kind", "subdomain", "tool", "hunter", "err", err.Error())
		return
	case "quake":
		// L1 适配器：需 env QUAKE_KEY
		p, err := quake.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "subdomain", "impl", "quake", "layer", "L1")
			return
		}
		logger.Info("L1 adapter init failed (env QUAKE_KEY required); falling back to mock",
			"kind", "subdomain", "tool", "quake", "err", err.Error())
		return
	}
	p, err := subfinder.New()
	if err == nil {
		registry.Register(p)
		logger.Info("plugin registered", "kind", "subdomain", "impl", "subfinder")
		return
	}
	logger.Info("plugin not installed; falling back to mock",
		"kind", "subdomain", "tool", "subfinder", "err", err.Error())
}

// registerFingerprintPlugin 按 FINGERPRINT_PLUGIN env 注册 fingerprint 真插件。
// 支持值："httpx"（default，仅 HTTP/HTTPS）/ "fingerprintx"（30+ TCP/UDP 服务）。
// 多 agent 部署时一组装 httpx 走 Web，一组装 fingerprintx 走非 Web 服务。
func registerFingerprintPlugin(registry *plugin.Registry, logger *log.Logger) {
	choice := envOrDefault("FINGERPRINT_PLUGIN", "httpx")
	if choice == "fingerprintx" {
		p, err := fingerprintx.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "fingerprint", "impl", "fingerprintx")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "fingerprint", "tool", "fingerprintx", "err", err.Error())
		return
	}
	p, err := httpx.NewFingerprint()
	if err == nil {
		registry.Register(p)
		logger.Info("plugin registered", "kind", "fingerprint", "impl", "httpx")
		return
	}
	logger.Info("plugin not installed; falling back to mock",
		"kind", "fingerprint", "tool", "httpx", "err", err.Error())
}

// registerWebCrawlPlugin 按 WEB_CRAWL_PLUGIN env 注册 web_crawl 真插件。
// 支持值："httpx"（default，仅 URL 探活）/ "katana"（DOM + JS 主动爬）/
// "gospider"（sitemap + robots + linkfinder 主动爬）/ "wayback"（被动归档）。
func registerWebCrawlPlugin(registry *plugin.Registry, logger *log.Logger) {
	choice := envOrDefault("WEB_CRAWL_PLUGIN", "httpx")
	switch choice {
	case "katana":
		p, err := katana.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "web_crawl", "impl", "katana")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "web_crawl", "tool", "katana", "err", err.Error())
		return
	case "gospider":
		p, err := gospider.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "web_crawl", "impl", "gospider")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "web_crawl", "tool", "gospider", "err", err.Error())
		return
	case "wayback":
		p, err := wayback.New()
		if err == nil {
			registry.Register(p)
			logger.Info("plugin registered", "kind", "web_crawl", "impl", "wayback")
			return
		}
		logger.Info("plugin not installed; falling back to mock",
			"kind", "web_crawl", "tool", "waybackurls", "err", err.Error())
		return
	}
	p, err := httpx.NewWebCrawl()
	if err == nil {
		registry.Register(p)
		logger.Info("plugin registered", "kind", "web_crawl", "impl", "httpx")
		return
	}
	logger.Info("plugin not installed; falling back to mock",
		"kind", "web_crawl", "tool", "httpx", "err", err.Error())
}
