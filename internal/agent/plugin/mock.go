package plugin

import "context"

// MockPortScan / MockWebCrawl / MockSubdomain / MockFingerprint 是 PR-S9 之前
// 内嵌在 tasks.Loop 的 mockResults 拆出来的插件实现。dev / CI / 真工具未装
// 时 cmd/node 回落用。
//
// 数据保持与原 mockResults 一致（带 "(mock)" 后缀，便于识别）。

type mockPortScan struct{}

func (mockPortScan) Kind() string { return "port_scan" }
func (mockPortScan) IsMock() bool { return true }
func (mockPortScan) Run(_ context.Context, target, _ string, _ map[string]any) ([]map[string]any, error) {
	return []map[string]any{
		{"host": target, "port": 22, "service": "ssh", "banner": "OpenSSH 8.2 (mock)"},
		{"host": target, "port": 80, "service": "http", "banner": "nginx/1.18 (mock)"},
	}, nil
}

type mockWebCrawl struct{}

func (mockWebCrawl) Kind() string { return "web_crawl" }
func (mockWebCrawl) IsMock() bool { return true }
func (mockWebCrawl) Run(_ context.Context, target, _ string, _ map[string]any) ([]map[string]any, error) {
	return []map[string]any{
		{"url": target, "status": 200, "title": "Example Domain (mock)"},
	}, nil
}

type mockSubdomain struct{}

func (mockSubdomain) Kind() string { return "subdomain" }
func (mockSubdomain) IsMock() bool { return true }
func (mockSubdomain) Run(_ context.Context, target, _ string, _ map[string]any) ([]map[string]any, error) {
	return []map[string]any{
		{"name": "api." + target, "ip": "192.0.2.1"},
		{"name": "www." + target, "ip": "192.0.2.2"},
	}, nil
}

type mockFingerprint struct{}

func (mockFingerprint) Kind() string { return "fingerprint" }
func (mockFingerprint) IsMock() bool { return true }
func (mockFingerprint) Run(_ context.Context, target, _ string, _ map[string]any) ([]map[string]any, error) {
	return []map[string]any{
		{"target": target, "tech": []string{"nginx", "Vue.js"}},
	}, nil
}

// MockPortScan 等可用作真插件构造失败时的 fallback。
func MockPortScan() Plugin    { return mockPortScan{} }
func MockWebCrawl() Plugin    { return mockWebCrawl{} }
func MockSubdomain() Plugin   { return mockSubdomain{} }
func MockFingerprint() Plugin { return mockFingerprint{} }

// RegisterAllMock 一键把 4 类 mock 注册到 Registry；测试 / dev 用。
func RegisterAllMock(r *Registry) {
	r.Register(mockPortScan{})
	r.Register(mockWebCrawl{})
	r.Register(mockSubdomain{})
	r.Register(mockFingerprint{})
}
