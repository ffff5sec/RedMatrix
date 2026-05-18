// Package handler 提供 FingerprintService ConnectRPC（PR-S74）。
package handler

import (
	"context"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	fpv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/fingerprint/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/fingerprint/v1/fingerprintv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/fingerprint"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	identityhandler "github.com/ffff5sec/RedMatrix/internal/identity/handler"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
)

// writers 写权限（SA + PA）；TA / PlatformAuditor 只读。
var writers = []identitydomain.Role{
	identitydomain.RoleSuperAdmin,
	identitydomain.RoleProjectAdmin,
}

// MatcherInvalidator TenantMatcher.Invalidate 子集；CRUD 后让缓存秒级失效。
type MatcherInvalidator interface {
	Invalidate(tenantID string)
}

// Handler FingerprintService 实现。
type Handler struct {
	builtin     *fingerprint.Library
	repo        fingerprint.CustomRuleRepository
	authSvc     auth.Service
	audit       audithook.Hook
	invalidator MatcherInvalidator
}

var _ fingerprintv1connect.FingerprintServiceHandler = (*Handler)(nil)

// New 构造；builtin + repo + authSvc 必填。
func New(builtin *fingerprint.Library, repo fingerprint.CustomRuleRepository, authSvc auth.Service) (*Handler, error) {
	if builtin == nil || repo == nil || authSvc == nil {
		return nil, errx.New(errx.ErrInternal, "fingerprint.handler.New: 依赖不能为 nil")
	}
	return &Handler{builtin: builtin, repo: repo, authSvc: authSvc}, nil
}

// WithAudit 注入审计钩子。
func (h *Handler) WithAudit(a audithook.Hook) *Handler { h.audit = a; return h }

// WithInvalidator 注入缓存失效器（让 TenantMatcher CRUD 后秒级更新）。
func (h *Handler) WithInvalidator(inv MatcherInvalidator) *Handler {
	h.invalidator = inv
	return h
}

// === ListBuiltinRules ===

func (h *Handler) ListBuiltinRules(
	ctx context.Context,
	req *connect.Request[fpv1.ListBuiltinRulesRequest],
) (*connect.Response[fpv1.ListBuiltinRulesResponse], error) {
	if _, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header()); err != nil {
		return nil, toConnectError(err)
	}
	rules := h.builtin.Rules()
	out := make([]*fpv1.Rule, 0, len(rules))
	for _, r := range rules {
		out = append(out, &fpv1.Rule{
			Name:          r.Name,
			Fields:        r.Fields,
			Keyword:       r.Keyword,
			CaseSensitive: r.CaseSensitive,
			Source:        "builtin",
		})
	}
	return connect.NewResponse(&fpv1.ListBuiltinRulesResponse{Rules: out}), nil
}

// === ListCustomRules ===

func (h *Handler) ListCustomRules(
	ctx context.Context,
	req *connect.Request[fpv1.ListCustomRulesRequest],
) (*connect.Response[fpv1.ListCustomRulesResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	tenantID := p.TenantID
	if p.Role == identitydomain.RolePlatformAuditor && req.Msg.GetTenantId() != "" {
		tenantID = req.Msg.GetTenantId()
	}
	if tenantID == "" {
		return connect.NewResponse(&fpv1.ListCustomRulesResponse{}), nil
	}
	rows, err := h.repo.ListAllByTenant(ctx, tenantID)
	if err != nil {
		return nil, toConnectError(err)
	}
	out := make([]*fpv1.Rule, 0, len(rows))
	for _, r := range rows {
		out = append(out, customRuleToProto(r))
	}
	return connect.NewResponse(&fpv1.ListCustomRulesResponse{Rules: out}), nil
}

// === CreateCustomRule ===

func (h *Handler) CreateCustomRule(
	ctx context.Context,
	req *connect.Request[fpv1.CreateCustomRuleRequest],
) (*connect.Response[fpv1.CreateCustomRuleResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	createdBy := p.UserID
	rule := &fingerprint.CustomRule{
		TenantID:      p.TenantID,
		Name:          req.Msg.GetName(),
		Fields:        req.Msg.GetFields(),
		Keyword:       req.Msg.GetKeyword(),
		CaseSensitive: req.Msg.GetCaseSensitive(),
		Enabled:       req.Msg.GetEnabled(),
		Description:   req.Msg.GetDescription(),
		CreatedBy:     &createdBy,
	}
	if err := h.repo.Insert(ctx, rule); err != nil {
		return nil, toConnectError(err)
	}
	h.invalidate(p.TenantID)
	h.logAudit(ctx, "fingerprint_rule_created", req.Header(), p, rule.ID, rule.Name)
	return connect.NewResponse(&fpv1.CreateCustomRuleResponse{Rule: customRuleToProto(rule)}), nil
}

// === DeleteCustomRule ===

func (h *Handler) DeleteCustomRule(
	ctx context.Context,
	req *connect.Request[fpv1.DeleteCustomRuleRequest],
) (*connect.Response[fpv1.DeleteCustomRuleResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	// 跨租户防御：先查再校
	cur, err := h.repo.GetByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if cur == nil {
		return nil, toConnectError(errx.New(errx.ErrInvalidInput, "rule 不存在"))
	}
	if cur.TenantID != p.TenantID && p.Role != identitydomain.RoleSuperAdmin {
		return nil, toConnectError(errx.New(errx.ErrAuthzRoleInsufficient, "无权"))
	}
	if err := h.repo.SoftDelete(ctx, cur.ID); err != nil {
		return nil, toConnectError(err)
	}
	h.invalidate(cur.TenantID)
	h.logAudit(ctx, "fingerprint_rule_deleted", req.Header(), p, cur.ID, cur.Name)
	return connect.NewResponse(&fpv1.DeleteCustomRuleResponse{}), nil
}

// === ToggleCustomRule ===

func (h *Handler) ToggleCustomRule(
	ctx context.Context,
	req *connect.Request[fpv1.ToggleCustomRuleRequest],
) (*connect.Response[fpv1.ToggleCustomRuleResponse], error) {
	p, err := identityhandler.RequireAuth(ctx, h.authSvc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := identityhandler.RequireRole(p, writers...); err != nil {
		return nil, toConnectError(err)
	}
	cur, err := h.repo.GetByID(ctx, req.Msg.GetId())
	if err != nil {
		return nil, toConnectError(err)
	}
	if cur == nil {
		return nil, toConnectError(errx.New(errx.ErrInvalidInput, "rule 不存在"))
	}
	if cur.TenantID != p.TenantID && p.Role != identitydomain.RoleSuperAdmin {
		return nil, toConnectError(errx.New(errx.ErrAuthzRoleInsufficient, "无权"))
	}
	if err := h.repo.ToggleEnabled(ctx, cur.ID, req.Msg.GetEnabled()); err != nil {
		return nil, toConnectError(err)
	}
	cur.Enabled = req.Msg.GetEnabled()
	h.invalidate(cur.TenantID)
	action := "fingerprint_rule_disabled"
	if req.Msg.GetEnabled() {
		action = "fingerprint_rule_enabled"
	}
	h.logAudit(ctx, action, req.Header(), p, cur.ID, cur.Name)
	return connect.NewResponse(&fpv1.ToggleCustomRuleResponse{Rule: customRuleToProto(cur)}), nil
}

// === helpers ===

func (h *Handler) invalidate(tenantID string) {
	if h.invalidator != nil {
		h.invalidator.Invalidate(tenantID)
	}
}

func (h *Handler) logAudit(ctx context.Context, action string, header connectHeader, p *auth.UserPrincipal, ruleID, ruleName string) {
	if h.audit == nil {
		return
	}
	_ = h.audit.Log(ctx, audithook.Event{
		Action:        action,
		ResourceKind:  "fingerprint_rule",
		ResourceID:    ruleID,
		TenantID:      p.TenantID,
		ActorUserID:   p.UserID,
		ActorUsername: p.Username,
		Payload:       map[string]any{"name": ruleName},
	})
}

// connectHeader 兼容 connect.Request.Header() 形态。
type connectHeader interface{ Get(string) string }

func customRuleToProto(c *fingerprint.CustomRule) *fpv1.Rule {
	if c == nil {
		return nil
	}
	r := &fpv1.Rule{
		Id:            c.ID,
		Name:          c.Name,
		Fields:        c.Fields,
		Keyword:       c.Keyword,
		CaseSensitive: c.CaseSensitive,
		Source:        "custom",
		Enabled:       c.Enabled,
		Description:   c.Description,
		TenantId:      c.TenantID,
	}
	if c.CreatedBy != nil {
		v := *c.CreatedBy
		r.CreatedBy = &v
	}
	if !c.CreatedAt.IsZero() {
		r.CreatedAt = timestamppb.New(c.CreatedAt)
	}
	if !c.UpdatedAt.IsZero() {
		r.UpdatedAt = timestamppb.New(c.UpdatedAt)
	}
	return r
}

// toConnectError 把 *errx.DomainError 转 connect.Error；其他错误兜底 Internal。
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	return errx.ToConnect(err, "")
}
