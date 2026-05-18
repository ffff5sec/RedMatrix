package fingerprint

import (
	"context"
	"sync"
	"time"
)

// TenantMatcher 合并内嵌库 + 某 tenant 的自定义规则做 Match（PR-S74）。
//
// 缓存语义：内存里按 tenant 缓存 enabled 规则；TTL 过期 / Invalidate 后下次
// match 时重拉。CRUD handler 应在写完调 Invalidate 让变更秒级生效。
type TenantMatcher struct {
	builtin *Library
	repo    CustomRuleRepository
	ttl     time.Duration
	clock   func() time.Time

	mu    sync.RWMutex
	cache map[string]tenantCacheEntry // key = tenant_id
}

type tenantCacheEntry struct {
	rules    []*Rule
	loadedAt time.Time
}

// NewTenantMatcher 构造。builtin / repo 必填；ttl ≤ 0 用 60s 默认。
func NewTenantMatcher(builtin *Library, repo CustomRuleRepository, ttl time.Duration) *TenantMatcher {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &TenantMatcher{
		builtin: builtin,
		repo:    repo,
		ttl:     ttl,
		clock:   time.Now,
		cache:   map[string]tenantCacheEntry{},
	}
}

// Match 对 (tenant, data) 跑「内嵌 + 该 tenant 自定义」全部规则；返命中 tech 名。
//
// 拉取失败 → 用 builtin 兜底（不阻断 match 主流程）。
func (m *TenantMatcher) Match(tenantID string, data map[string]any) []string {
	if m == nil || len(data) == 0 {
		return nil
	}
	rules := m.rulesFor(tenantID)
	if len(rules) == 0 {
		return nil
	}
	// 复用现有 Library.Match 算法：临时 lib 包装合并后的规则
	tmp := &Library{rules: rules}
	return tmp.Match(data)
}

// Invalidate 清某 tenant 的缓存（CRUD 后立即调）。
func (m *TenantMatcher) Invalidate(tenantID string) {
	m.mu.Lock()
	delete(m.cache, tenantID)
	m.mu.Unlock()
}

// rulesFor 取合并规则；优先用缓存。
func (m *TenantMatcher) rulesFor(tenantID string) []*Rule {
	// 1) cache hit
	m.mu.RLock()
	e, ok := m.cache[tenantID]
	m.mu.RUnlock()
	if ok && m.clock().Sub(e.loadedAt) < m.ttl {
		return e.rules
	}

	// 2) miss → 拉自定义 + 合并
	merged := append([]*Rule{}, m.builtinRules()...)
	if tenantID != "" && m.repo != nil {
		customs, err := m.repo.ListEnabledByTenant(context.Background(), tenantID)
		if err == nil {
			for _, c := range customs {
				if r := c.ToRule(); r != nil {
					merged = append(merged, r)
				}
			}
		}
		// err 静默：fall back 到 builtin（避免 DB 抖动影响扫描结果）
	}

	m.mu.Lock()
	m.cache[tenantID] = tenantCacheEntry{rules: merged, loadedAt: m.clock()}
	m.mu.Unlock()
	return merged
}

func (m *TenantMatcher) builtinRules() []*Rule {
	if m.builtin == nil {
		return nil
	}
	return m.builtin.rules
}

// BuiltinOnlyMatcher 仅用 builtin 库（不查 tenant 自定义；适合 dev / 无 PG 场景）。
// 实现 scan.FingerprintMatcher 接口（Match(tenantID, data)）。
type BuiltinOnlyMatcher struct{ lib *Library }

// NewBuiltinOnlyMatcher 构造。
func NewBuiltinOnlyMatcher(lib *Library) *BuiltinOnlyMatcher {
	return &BuiltinOnlyMatcher{lib: lib}
}

// Match 实现 scan.FingerprintMatcher；忽略 tenantID。
func (m *BuiltinOnlyMatcher) Match(_ string, data map[string]any) []string {
	if m == nil || m.lib == nil {
		return nil
	}
	return m.lib.Match(data)
}
