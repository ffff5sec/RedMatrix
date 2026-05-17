package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// AuthSvc 最小 auth.Service 子集。
type AuthSvc interface {
	AuthenticateBearer(ctx context.Context, raw string) (*auth.UserPrincipal, error)
}

// MembershipLookup PA 路径取项目集。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

// Handler 通用导出 HTTP 入口；按 path 后缀分发到对应 Resource。
//
// 路由：
//
//	GET /api/v1/export/<resource>?format=csv|json&<resource-specific>
//
// 鉴权：Authorization: Bearer <jwt | rmk_xxx>
//
// 行为：成功 200 + Content-Disposition: attachment；失败 4xx + JSON {error}。
type Handler struct {
	authSvc   AuthSvc
	memberDB  MembershipLookup
	resources map[string]Resource
	auditFor  map[string]string // resource name → audit action kind
	audit     audithook.Hook
	logger    *log.Logger
	clock     func() time.Time
}

// New 构造。
func New(authSvc AuthSvc, memberDB MembershipLookup, logger *log.Logger) *Handler {
	return &Handler{
		authSvc:   authSvc,
		memberDB:  memberDB,
		resources: map[string]Resource{},
		auditFor:  map[string]string{},
		logger:    logger,
		clock:     time.Now,
	}
}

// WithAudit 链式注入审计钩子。
func (h *Handler) WithAudit(a audithook.Hook) *Handler { h.audit = a; return h }

// Register 注册资源 + 对应的审计 action kind。
func (h *Handler) Register(r Resource, auditAction string) *Handler {
	h.resources[r.Name()] = r
	h.auditFor[r.Name()] = auditAction
	return h
}

// Path 路由前缀。
func Path() string { return "/api/v1/export/" }

// ServeHTTP 入口。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "仅支持 GET")
		return
	}

	// 解析 resource
	resourceName := strings.TrimPrefix(r.URL.Path, Path())
	resourceName = strings.TrimSuffix(resourceName, "/")
	if resourceName == "" || strings.Contains(resourceName, "/") {
		writeErr(w, http.StatusNotFound, "UNKNOWN_RESOURCE", "导出资源未注册")
		return
	}
	resource, ok := h.resources[resourceName]
	if !ok {
		writeErr(w, http.StatusNotFound, "UNKNOWN_RESOURCE", "导出资源未注册: "+resourceName)
		return
	}

	// 鉴权
	principal, err := h.authenticate(r)
	if err != nil {
		code, msg := errFields(err)
		writeErr(w, http.StatusUnauthorized, code, msg)
		return
	}

	// 解析 format
	q := r.URL.Query()
	formatName := strings.ToLower(strings.TrimSpace(q.Get("format")))
	if formatName == "" {
		formatName = "csv"
	}
	var format Format
	switch formatName {
	case "csv":
		format = CSVFormat{}
	case "json":
		format = &JSONFormat{}
	default:
		writeErr(w, http.StatusBadRequest, "INVALID_FORMAT", "format 必须是 csv 或 json")
		return
	}

	// 构造 RBAC scope
	scope, err := h.buildScope(r.Context(), principal, q)
	if err != nil {
		code, msg := errFields(err)
		writeErr(w, http.StatusForbidden, code, msg)
		return
	}

	// 响应头：附件下载 + 不缓存
	filename := fmt.Sprintf("%s-%s.%s", resource.Name(), h.clock().UTC().Format("20060102-150405"), format.Extension())
	w.Header().Set("Content-Type", format.ContentType())
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	cols := resource.Columns()
	if err := format.WriteHeader(w, cols); err != nil {
		// 头都写不出 — 没法再 set status；只 log
		if h.logger != nil {
			h.logger.LogError(r.Context(), "export: write header failed", err, "resource", resource.Name())
		}
		return
	}
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	count := 0
	streamErr := resource.Stream(r.Context(), scope, func(row Row) error {
		if err := format.WriteRow(w, cols, row); err != nil {
			return err
		}
		count++
		// 每 200 行 flush，让浏览器渐显
		if flusher != nil && count%200 == 0 {
			flusher.Flush()
		}
		return nil
	})
	if streamErr != nil && h.logger != nil {
		h.logger.LogError(r.Context(), "export: stream error", streamErr,
			"resource", resource.Name(), "count", count)
	}
	if err := format.Close(w); err != nil && h.logger != nil {
		h.logger.LogError(r.Context(), "export: close error", err)
	}
	if flusher != nil {
		flusher.Flush()
	}

	// 审计（best-effort）
	if h.audit != nil {
		action := h.auditFor[resource.Name()]
		if action != "" {
			_ = h.audit.Log(r.Context(), audithook.Event{
				Action:        action,
				ResourceKind:  resource.Name(),
				TenantID:      principal.TenantID,
				ActorUserID:   principal.UserID,
				ActorUsername: principal.Username,
				ActorIP:       clientIP(r),
				UserAgent:     r.UserAgent(),
				Payload: map[string]any{
					"format": format.Extension(),
					"count":  count,
					"query":  flatQuery(q),
				},
			})
		}
	}
}

func (h *Handler) authenticate(r *http.Request) (*auth.UserPrincipal, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errx.New(errx.ErrAuthFailed, "缺 Authorization: Bearer header")
	}
	token := strings.TrimSpace(authHeader[len("Bearer "):])
	if token == "" {
		return nil, errx.New(errx.ErrAuthFailed, "Bearer token 为空")
	}
	return h.authSvc.AuthenticateBearer(r.Context(), token)
}

func (h *Handler) buildScope(ctx context.Context, p *auth.UserPrincipal, q map[string][]string) (Scope, error) {
	scope := Scope{Query: q}
	switch p.Role {
	case identitydomain.RoleSuperAdmin, identitydomain.RolePlatformAuditor:
		// 跨租户；不限 tenant + 不限项目（resource 自己处理可选 tenant_id 过滤）
	case identitydomain.RoleTenantAuditor:
		scope.TenantID = p.TenantID
	case identitydomain.RoleProjectAdmin:
		scope.TenantID = p.TenantID
		if h.memberDB == nil {
			return Scope{}, errx.New(errx.ErrInternal, "PA 路径需 memberDB")
		}
		ids, err := h.memberDB.ListProjectIDsByUser(ctx, p.UserID)
		if err != nil {
			return Scope{}, err
		}
		if ids == nil {
			ids = []string{} // 显式 0 项目；resource 应短路返空
		}
		scope.ProjectIDs = ids
	default:
		return Scope{}, errx.New(errx.ErrAuthFailed, "未知角色").WithFields("role", string(p.Role))
	}
	return scope, nil
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	// 用 json.Marshal 而非手拼字符串，避开 gosec G705 + 自动转义
	body, err := json.Marshal(struct {
		Error   string `json:"error"`
		Message string `json:"message,omitempty"`
	}{Error: code, Message: msg})
	if err != nil {
		// 极少触发；回退到固定文本
		body = []byte(`{"error":"INTERNAL"}`)
	}
	_, _ = w.Write(body)
}

func errFields(err error) (code, msg string) {
	if err == nil {
		return "", ""
	}
	if c, ok := errx.GetCode(err); ok {
		return string(c), err.Error()
	}
	var de *errx.DomainError
	if errors.As(err, &de) {
		return string(de.Code), de.Error()
	}
	return "INTERNAL", err.Error()
}

func clientIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	return r.RemoteAddr
}

func flatQuery(q map[string][]string) map[string]string {
	out := make(map[string]string, len(q))
	for k, v := range q {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}
