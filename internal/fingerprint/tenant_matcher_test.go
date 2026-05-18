package fingerprint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === stub CustomRuleRepository ===

type stubRepo struct {
	rules   []*CustomRule
	calls   int
	listErr error
}

func (s *stubRepo) Insert(_ context.Context, _ *CustomRule) error { return nil }
func (s *stubRepo) GetByID(_ context.Context, _ string) (*CustomRule, error) {
	return nil, nil
}
func (s *stubRepo) ListEnabledByTenant(_ context.Context, _ string) ([]*CustomRule, error) {
	s.calls++
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.rules, nil
}
func (s *stubRepo) ListAllByTenant(_ context.Context, _ string) ([]*CustomRule, error) {
	return s.rules, nil
}
func (s *stubRepo) SoftDelete(_ context.Context, _ string) error            { return nil }
func (s *stubRepo) ToggleEnabled(_ context.Context, _ string, _ bool) error { return nil }

// === BuiltinOnlyMatcher ===

func TestBuiltinOnlyMatcher_HitsBuiltinIgnoresTenant(t *testing.T) {
	m := NewBuiltinOnlyMatcher(Default())
	hits := m.Match("any-tenant", map[string]any{"webserver": "nginx/1.20"})
	assert.Contains(t, hits, "nginx")
}

// === TenantMatcher ===

func TestTenantMatcher_MergesBuiltinAndCustom(t *testing.T) {
	repo := &stubRepo{rules: []*CustomRule{
		{Name: "MyCustomTag", Fields: []string{"body"}, Keyword: "MY_SECRET_BANNER", Enabled: true},
	}}
	m := NewTenantMatcher(Default(), repo, time.Minute)
	hits := m.Match("t1", map[string]any{
		"webserver": "nginx/1.20",
		"body":      "...content with MY_SECRET_BANNER inside...",
	})
	assert.Contains(t, hits, "nginx")
	assert.Contains(t, hits, "MyCustomTag")
}

func TestTenantMatcher_CachesAcrossCalls(t *testing.T) {
	repo := &stubRepo{rules: []*CustomRule{
		{Name: "X", Keyword: "wp-content", Enabled: true},
	}}
	m := NewTenantMatcher(Default(), repo, time.Minute)
	for i := 0; i < 5; i++ {
		_ = m.Match("t1", map[string]any{"body": "wp-content"})
	}
	assert.Equal(t, 1, repo.calls, "1 个 tenant 5 次 match 应只查 DB 一次")
}

func TestTenantMatcher_CacheExpiresAfterTTL(t *testing.T) {
	repo := &stubRepo{rules: []*CustomRule{
		{Name: "X", Keyword: "wp-content", Enabled: true},
	}}
	now := time.Now()
	m := NewTenantMatcher(Default(), repo, 100*time.Millisecond)
	m.clock = func() time.Time { return now }

	_ = m.Match("t1", map[string]any{"body": "wp-content"})
	now = now.Add(200 * time.Millisecond)
	_ = m.Match("t1", map[string]any{"body": "wp-content"})
	assert.Equal(t, 2, repo.calls, "TTL 过后应重拉")
}

func TestTenantMatcher_InvalidateForcesRefetch(t *testing.T) {
	repo := &stubRepo{rules: []*CustomRule{
		{Name: "X", Keyword: "wp-content", Enabled: true},
	}}
	m := NewTenantMatcher(Default(), repo, time.Hour)
	_ = m.Match("t1", map[string]any{"body": "wp-content"})
	m.Invalidate("t1")
	_ = m.Match("t1", map[string]any{"body": "wp-content"})
	assert.Equal(t, 2, repo.calls)
}

func TestTenantMatcher_RepoErrorFallsBackToBuiltin(t *testing.T) {
	repo := &stubRepo{listErr: assertErr("db boom")}
	m := NewTenantMatcher(Default(), repo, time.Minute)
	hits := m.Match("t1", map[string]any{"webserver": "nginx/1.20"})
	// 自定义 rules 拉失败但 builtin 仍命中
	assert.Contains(t, hits, "nginx")
}

func TestTenantMatcher_EmptyTenantUsesBuiltinOnly(t *testing.T) {
	repo := &stubRepo{rules: []*CustomRule{
		{Name: "X", Keyword: "wp-content", Enabled: true},
	}}
	m := NewTenantMatcher(Default(), repo, time.Minute)
	hits := m.Match("", map[string]any{"webserver": "nginx/1.20", "body": "wp-content"})
	assert.Contains(t, hits, "nginx")
	assert.NotContains(t, hits, "X", "空 tenant 不该带自定义")
	assert.Equal(t, 0, repo.calls, "空 tenant 不查 DB")
}

// === domain.CustomRule Validate ===

func TestCustomRule_ValidateForCreate_RequiresNameAndKeyword(t *testing.T) {
	c := &CustomRule{TenantID: "t1", Keyword: "x"}
	require.Error(t, c.ValidateForCreate())
	c = &CustomRule{TenantID: "t1", Name: "n"}
	require.Error(t, c.ValidateForCreate())
	c = &CustomRule{Name: "n", Keyword: "x"}
	require.Error(t, c.ValidateForCreate(), "缺 tenant_id")
}

func TestCustomRule_ToRule_PropagatesFields(t *testing.T) {
	c := &CustomRule{
		Name: "abc", Fields: []string{"body"}, Keyword: "kw", CaseSensitive: true,
	}
	r := c.ToRule()
	assert.Equal(t, "abc", r.Name)
	assert.Equal(t, []string{"body"}, r.Fields)
	assert.True(t, r.CaseSensitive)
	assert.Equal(t, "custom", r.Source)
}

// === helpers ===

type assertErr string

func (e assertErr) Error() string { return string(e) }
