package log

import "context"

// 日志 ctx 元数据 key。值为 string，故未导出 type 别名以防外部误用 string 直接 set。
type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyUserID
	ctxKeyTenantID
	ctxKeyProjectID
	ctxKeyRole
)

// === Setter（拦截器 / 中间件用） ===

// WithRequestID 注入 request_id（来自 X-Request-ID header / 拦截器生成）。
func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRequestID, id)
}

// WithUserID 注入登录用户 ID。
func WithUserID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyUserID, id)
}

// WithTenantID 注入租户 ID。
func WithTenantID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyTenantID, id)
}

// WithProjectID 注入项目 ID（业务 RPC 通常携带）。
func WithProjectID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyProjectID, id)
}

// WithRole 注入调用方角色（SuperAdmin / ProjectAdmin / TenantAuditor / PlatformAuditor）。
func WithRole(ctx context.Context, role string) context.Context {
	if role == "" {
		return ctx
	}
	return context.WithValue(ctx, ctxKeyRole, role)
}

// === Getter（业务代码读取场景较少；主要给 log/audit 用） ===

func RequestIDFromContext(ctx context.Context) string { return ctxString(ctx, ctxKeyRequestID) }
func UserIDFromContext(ctx context.Context) string    { return ctxString(ctx, ctxKeyUserID) }
func TenantIDFromContext(ctx context.Context) string  { return ctxString(ctx, ctxKeyTenantID) }
func ProjectIDFromContext(ctx context.Context) string { return ctxString(ctx, ctxKeyProjectID) }
func RoleFromContext(ctx context.Context) string      { return ctxString(ctx, ctxKeyRole) }

func ctxString(ctx context.Context, k ctxKey) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(k).(string)
	return v
}

// ctxAttrs 提取已注入的 ctx 元数据为 slog attr 列表（key, value 交替）。
// 字段名与 docs/LLD/03-error-catalog.md §6 示例严格一致。
func ctxAttrs(ctx context.Context) []any {
	if ctx == nil {
		return nil
	}
	pairs := []struct {
		key  string
		ckey ctxKey
	}{
		{"request_id", ctxKeyRequestID},
		{"user_id", ctxKeyUserID},
		{"tenant_id", ctxKeyTenantID},
		{"project_id", ctxKeyProjectID},
		{"role", ctxKeyRole},
	}
	out := make([]any, 0, len(pairs)*2)
	for _, p := range pairs {
		if v := ctxString(ctx, p.ckey); v != "" {
			out = append(out, p.key, v)
		}
	}
	return out
}
