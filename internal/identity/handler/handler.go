// Package handler 是 identity 模块的 ConnectRPC 适配层。
//
// 职责：
//   - proto request → service 调用 → proto response
//   - 从 HTTP header 提取 client IP / User-Agent（注入 LoginRequest）
//   - 从 Authorization header 提取 Bearer，调 AuthenticateBearer 拿 UserPrincipal
//     —— 暂未挂全局 Auth Interceptor，每个受保护 RPC 用 RequireAuth helper
//   - errx.DomainError → connect.Error 错码映射
//
// 不在本包范围：
//   - Authz interceptor（按 allowed_roles 注解强制）—— 后续 PR
//   - Audit interceptor（auth.* 事件落库）—— 后续 PR
package handler

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	identityv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/identity/v1/identityv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	"github.com/ffff5sec/RedMatrix/internal/identity/policy"
)

// Handler 实现 identityv1connect.IdentityServiceHandler。
type Handler struct {
	svc     auth.Service
	captcha policy.Captcha // 可空（GetCaptcha 时返 NOT_IMPLEMENTED）
}

// 编译期断言：实现 IdentityServiceHandler 接口
var _ identityv1connect.IdentityServiceHandler = (*Handler)(nil)

// New 构造 IdentityService handler。
func New(svc auth.Service, captcha policy.Captcha) (*Handler, error) {
	if svc == nil {
		return nil, errx.New(errx.ErrInternal, "handler.New: svc 不能为 nil")
	}
	return &Handler{svc: svc, captcha: captcha}, nil
}

// === GetCaptcha ===

func (h *Handler) GetCaptcha(
	ctx context.Context,
	_ *connect.Request[identityv1.GetCaptchaRequest],
) (*connect.Response[identityv1.GetCaptchaResponse], error) {
	if h.captcha == nil {
		return nil, toConnectError(errx.New(errx.ErrNotImplemented, "captcha 未启用"))
	}
	ch, err := h.captcha.Generate(ctx)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.GetCaptchaResponse{
		CaptchaId: ch.ID,
		ImagePng:  ch.Image,
	}), nil
}

// === Login ===

func (h *Handler) Login(
	ctx context.Context,
	req *connect.Request[identityv1.LoginRequest],
) (*connect.Response[identityv1.LoginResponse], error) {
	in := req.Msg

	loginReq := auth.LoginRequest{
		Username:  in.GetUsername(),
		Password:  in.GetPassword(),
		ClientIP:  clientIP(req.Header()),
		UserAgent: userAgent(req.Header()),
	}
	if v := in.GetCaptchaId(); v != "" {
		loginReq.CaptchaID = v
	}
	if v := in.GetCaptchaAnswer(); v != "" {
		loginReq.CaptchaAnswer = v
	}

	res, err := h.svc.Login(ctx, loginReq)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.LoginResponse{
		AccessToken:        res.AccessToken,
		ExpiresAt:          timestampProto(res.ExpiresAt),
		User:               userToProto(res.User),
		MustChangePassword: res.MustChangePassword,
		LandingUrl:         res.LandingURL,
	}), nil
}

// === GetCurrentUser / ChangePassword ===

func (h *Handler) GetCurrentUser(
	ctx context.Context,
	req *connect.Request[identityv1.GetCurrentUserRequest],
) (*connect.Response[identityv1.GetCurrentUserResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	u, err := h.svc.GetCurrentUser(ctx, p.UserID)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.GetCurrentUserResponse{
		User: userToProto(u),
	}), nil
}

func (h *Handler) ChangePassword(
	ctx context.Context,
	req *connect.Request[identityv1.ChangePasswordRequest],
) (*connect.Response[identityv1.ChangePasswordResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	// API Key 凭证不能改密（API Key 自身不持密码）
	if p.Source != auth.PrincipalSourceJWT {
		return nil, toConnectError(errx.New(errx.ErrInvalidInput,
			"ChangePassword 仅 JWT 凭证可调；API Key 请走 Revoke + 重建"))
	}

	if err := h.svc.ChangePassword(ctx, p.UserID,
		req.Msg.GetCurrentPassword(), req.Msg.GetNewPassword()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.ChangePasswordResponse{
		AllSessionsRevoked: true, // 当前实现总是 true（tv++）
	}), nil
}

// === Logout ===

func (h *Handler) Logout(
	ctx context.Context,
	req *connect.Request[identityv1.LogoutRequest],
) (*connect.Response[identityv1.LogoutResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if p.SessionID == "" {
		// API Key 路径无 session（rmk_ token 不能调 Logout）
		return nil, toConnectError(errx.New(errx.ErrInvalidInput,
			"API Key 凭证不能调 Logout；用 RevokeAPIKey"))
	}
	if err := h.svc.Logout(ctx, p.SessionID); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.LogoutResponse{}), nil
}

// === LogoutAllSessions ===

func (h *Handler) LogoutAllSessions(
	ctx context.Context,
	req *connect.Request[identityv1.LogoutAllSessionsRequest],
) (*connect.Response[identityv1.LogoutAllSessionsResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.LogoutAllSessions(ctx, p.UserID); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.LogoutAllSessionsResponse{}), nil
}

// === API Key CRUD ===

func (h *Handler) ListAPIKeys(
	ctx context.Context,
	req *connect.Request[identityv1.ListAPIKeysRequest],
) (*connect.Response[identityv1.ListAPIKeysResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	keys, err := h.svc.ListAPIKeys(ctx, p.UserID)
	if err != nil {
		return nil, toConnectError(err)
	}
	pbKeys := make([]*identityv1.APIKey, 0, len(keys))
	for _, k := range keys {
		pbKeys = append(pbKeys, apiKeyToProto(k))
	}
	return connect.NewResponse(&identityv1.ListAPIKeysResponse{Keys: pbKeys}), nil
}

func (h *Handler) CreateAPIKey(
	ctx context.Context,
	req *connect.Request[identityv1.CreateAPIKeyRequest],
) (*connect.Response[identityv1.CreateAPIKeyResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	in := req.Msg

	createReq := auth.CreateAPIKeyRequest{
		UserID: p.UserID,
		Name:   in.GetName(),
		Scopes: in.GetScopes(),
	}
	if exp := in.GetExpiresAt(); exp != nil {
		t := exp.AsTime()
		createReq.ExpiresAt = &t
	}

	res, err := h.svc.CreateAPIKey(ctx, createReq)
	if err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.CreateAPIKeyResponse{
		Key:    apiKeyToProto(res.Key),
		Secret: res.Plaintext,
	}), nil
}

func (h *Handler) RevokeAPIKey(
	ctx context.Context,
	req *connect.Request[identityv1.RevokeAPIKeyRequest],
) (*connect.Response[identityv1.RevokeAPIKeyResponse], error) {
	p, err := RequireAuth(ctx, h.svc, req.Header())
	if err != nil {
		return nil, toConnectError(err)
	}
	if err := h.svc.RevokeAPIKey(ctx, p.UserID, req.Msg.GetId()); err != nil {
		return nil, toConnectError(err)
	}
	return connect.NewResponse(&identityv1.RevokeAPIKeyResponse{}), nil
}

// === error mapping ===

// toConnectError 把 errx.DomainError → connect.Error。
//
// 把 domain Code 字符串塞进 connect Error 的 detail（前端 / SDK 可读）；
// connect.Code 走 errx 注册的映射表。
func toConnectError(err error) error {
	if err == nil {
		return nil
	}
	var de *errx.DomainError
	if errors.As(err, &de) {
		ce := connect.NewError(de.ConnectCode(),
			errors.New(string(de.Code)+": "+de.Message))
		// detail：把 errx.Code 也以独立字节串挂上，方便结构化解析（占位实现，
		// 后续 PR 接 connect.ErrorDetail 标准格式）
		return ce
	}
	return connect.NewError(connect.CodeInternal, err)
}
