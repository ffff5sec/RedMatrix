package ctxmeta

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// === setter / getter ===

func TestRoundtrip_AllFields(t *testing.T) {
	ctx := context.Background()
	ctx = WithRequestID(ctx, "req_1")
	ctx = WithUserID(ctx, "u_1")
	ctx = WithTenantID(ctx, "t_1")
	ctx = WithProjectID(ctx, "p_1")
	ctx = WithRole(ctx, "SuperAdmin")

	assert.Equal(t, "req_1", RequestIDFromContext(ctx))
	assert.Equal(t, "u_1", UserIDFromContext(ctx))
	assert.Equal(t, "t_1", TenantIDFromContext(ctx))
	assert.Equal(t, "p_1", ProjectIDFromContext(ctx))
	assert.Equal(t, "SuperAdmin", RoleFromContext(ctx))
}

func TestSetter_EmptyStringSilent(t *testing.T) {
	ctx := context.Background()
	ctx2 := WithRequestID(ctx, "")
	assert.Equal(t, "", RequestIDFromContext(ctx2))

	ctx3 := WithUserID(WithRequestID(ctx, "x"), "")
	assert.Equal(t, "x", RequestIDFromContext(ctx3))
	assert.Equal(t, "", UserIDFromContext(ctx3))
}

func TestSetter_OverrideReplaces(t *testing.T) {
	ctx := WithRequestID(context.Background(), "first")
	ctx = WithRequestID(ctx, "second")
	assert.Equal(t, "second", RequestIDFromContext(ctx))
}

// === nil-safe ===

func TestGetter_NilCtxReturnsEmpty(t *testing.T) {
	//nolint:staticcheck // 故意 nil ctx
	assert.Equal(t, "", RequestIDFromContext(nil))
	//nolint:staticcheck
	assert.Equal(t, "", UserIDFromContext(nil))
	//nolint:staticcheck
	assert.Equal(t, "", TenantIDFromContext(nil))
	//nolint:staticcheck
	assert.Equal(t, "", ProjectIDFromContext(nil))
	//nolint:staticcheck
	assert.Equal(t, "", RoleFromContext(nil))
}

func TestGetter_BackgroundReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", RequestIDFromContext(ctx))
	assert.Equal(t, "", UserIDFromContext(ctx))
}

// === Attrs ===

func TestAttrs_AllFieldsExpanded(t *testing.T) {
	ctx := context.Background()
	ctx = WithRequestID(ctx, "r")
	ctx = WithUserID(ctx, "u")
	ctx = WithTenantID(ctx, "t")
	ctx = WithProjectID(ctx, "p")
	ctx = WithRole(ctx, "ProjectAdmin")

	got := Attrs(ctx)
	require.NotNil(t, got)
	require.Len(t, got, 10) // 5 pairs

	// Convert to map for order-independent assertion
	m := pairsToMap(got)
	assert.Equal(t, "r", m["request_id"])
	assert.Equal(t, "u", m["user_id"])
	assert.Equal(t, "t", m["tenant_id"])
	assert.Equal(t, "p", m["project_id"])
	assert.Equal(t, "ProjectAdmin", m["role"])
}

func TestAttrs_PartialFields(t *testing.T) {
	ctx := WithRequestID(context.Background(), "r")
	ctx = WithUserID(ctx, "u")

	got := Attrs(ctx)
	assert.Len(t, got, 4) // 2 pairs
	m := pairsToMap(got)
	assert.Equal(t, "r", m["request_id"])
	assert.Equal(t, "u", m["user_id"])
	_, hasTenant := m["tenant_id"]
	assert.False(t, hasTenant)
}

func TestAttrs_EmptyCtxNoAttrs(t *testing.T) {
	assert.Empty(t, Attrs(context.Background()))
}

func TestAttrs_NilCtx(t *testing.T) {
	//nolint:staticcheck // nil ctx 防御
	assert.Nil(t, Attrs(nil))
}

// === 防外部撞键 ===
//
// ctxKey 是未导出类型；外部包无法构造同 key 直接 ctx.WithValue。
// 这是设计：保证只能通过本包 setter 写入，避免误用。

func TestExternalCannotShadow(t *testing.T) {
	// 用 string key 写入不会被 RequestIDFromContext 取到（不同 key type）
	ctx := context.WithValue(context.Background(), "request_id", "imposter") //nolint:revive,staticcheck // 故意用 string key
	assert.Equal(t, "", RequestIDFromContext(ctx))
}

// === helpers ===

func pairsToMap(pairs []any) map[string]string {
	m := make(map[string]string, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		k, _ := pairs[i].(string)
		v, _ := pairs[i+1].(string)
		m[k] = v
	}
	return m
}
