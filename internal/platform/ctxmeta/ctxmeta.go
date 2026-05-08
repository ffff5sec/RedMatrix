// Package ctxmeta 是 RedMatrix 后端跨包共享的 context 元数据钩子。
//
// 单一真相源：5 个 ctx key（request_id / user_id / tenant_id / project_id / role）
// 与对应 setter / getter / slog Attrs 展开，供以下消费者共用：
//   - internal/platform/log     — WithCtx 自动注入到结构化日志字段
//   - internal/platform/eventbus/outbox — PublishTx 写 outbox.trace_id / tenant_id
//   - internal/platform/metrics — 后续业务指标按租户 / 角色聚合
//   - internal/audit  (待落)    — 审计日志关联请求链路
//   - internal/rls    (待落)    — RLS session var 注入
//
// 字段名与 docs/LLD/03-error-catalog.md §6 / 50-frontend-arch §5.3 一致。
//
// 设计要点：
//   - ctxKey 是未导出 type，外部代码无法直接 ctx.Value 取（强制走 *FromContext）
//   - 空 string 会被 With* 静默忽略（不污染 ctx）
//   - 所有 *FromContext 在 nil ctx 时返回空字串（不 panic）
package ctxmeta

import "context"

// ctxKey 是包内私有 key 类型，防止外部 ctx.Value 直接撞键。
type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyUserID
	keyTenantID
	keyProjectID
	keyRole
	keyNodeID
)

// === Setter ===

// WithRequestID 注入 request_id（一般来自 X-Request-ID header / 拦截器生成）。
// 也作为 outbox.trace_id 的来源。
func WithRequestID(ctx context.Context, id string) context.Context {
	return setIfNonEmpty(ctx, keyRequestID, id)
}

// WithUserID 注入登录用户 ID。
func WithUserID(ctx context.Context, id string) context.Context {
	return setIfNonEmpty(ctx, keyUserID, id)
}

// WithTenantID 注入租户 ID。
func WithTenantID(ctx context.Context, id string) context.Context {
	return setIfNonEmpty(ctx, keyTenantID, id)
}

// WithProjectID 注入项目 ID（业务 RPC 通常携带）。
func WithProjectID(ctx context.Context, id string) context.Context {
	return setIfNonEmpty(ctx, keyProjectID, id)
}

// WithRole 注入调用方角色（SuperAdmin / ProjectAdmin / TenantAuditor / PlatformAuditor）。
func WithRole(ctx context.Context, role string) context.Context {
	return setIfNonEmpty(ctx, keyRole, role)
}

// WithNodeID 注入 mTLS-认证的节点 ID（PR-T4-D3 起；中间件按 cert 指纹反查）。
func WithNodeID(ctx context.Context, id string) context.Context {
	return setIfNonEmpty(ctx, keyNodeID, id)
}

// === Getter ===

func RequestIDFromContext(ctx context.Context) string { return get(ctx, keyRequestID) }
func UserIDFromContext(ctx context.Context) string    { return get(ctx, keyUserID) }
func TenantIDFromContext(ctx context.Context) string  { return get(ctx, keyTenantID) }
func ProjectIDFromContext(ctx context.Context) string { return get(ctx, keyProjectID) }
func RoleFromContext(ctx context.Context) string      { return get(ctx, keyRole) }
func NodeIDFromContext(ctx context.Context) string    { return get(ctx, keyNodeID) }

// === slog 展开 ===

// Attrs 把已注入的 ctx 元数据展开为 slog attr 列表（key, value 交替）。
// 用法（log 包内部）：logger.With(ctxmeta.Attrs(ctx)...)
//
// 字段名与 docs/LLD/03-error-catalog.md §6 示例严格一致：
//
//	{"request_id":"req_x","user_id":"u_y","tenant_id":"t_z",...}
func Attrs(ctx context.Context) []any {
	if ctx == nil {
		return nil
	}
	pairs := []struct {
		name string
		key  ctxKey
	}{
		{"request_id", keyRequestID},
		{"user_id", keyUserID},
		{"tenant_id", keyTenantID},
		{"project_id", keyProjectID},
		{"role", keyRole},
		{"node_id", keyNodeID},
	}
	out := make([]any, 0, len(pairs)*2)
	for _, p := range pairs {
		if v := get(ctx, p.key); v != "" {
			out = append(out, p.name, v)
		}
	}
	return out
}

// === 私有 helper ===

func setIfNonEmpty(ctx context.Context, k ctxKey, v string) context.Context {
	if v == "" {
		return ctx
	}
	return context.WithValue(ctx, k, v)
}

func get(ctx context.Context, k ctxKey) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(k).(string)
	return v
}
