package handler

import (
	"context"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
)

// RequireAuth 从 Authorization header 取 Bearer，调 svc.AuthenticateBearer。
//
// 错码：
//   - header 缺 / 格式错 / 不是 Bearer → ErrAuthTokenInvalid
//   - svc 返错原样透传（含 AUTH_FAILED / AUTH_TOKEN_EXPIRED 等）
//
// 全局 Auth Interceptor 落地后此 helper 应被替换为 ctx.principal 读取。
func RequireAuth(ctx context.Context, svc auth.Service, header http.Header) (*auth.UserPrincipal, error) {
	raw := header.Get("Authorization")
	if raw == "" {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "缺少 Authorization header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(raw, prefix) {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "Authorization header 必须以 Bearer 开头")
	}
	token := strings.TrimSpace(raw[len(prefix):])
	if token == "" {
		return nil, errx.New(errx.ErrAuthTokenInvalid, "Bearer token 为空")
	}
	return svc.AuthenticateBearer(ctx, token)
}

// clientIP 从请求 header 推断 client IP。
//
// 优先级：X-Forwarded-For 首段 > X-Real-IP > 直连地址（暂不可见，留 0 值）。
// 反代场景常见配置：nginx/Caddy 设置 X-Forwarded-For。
func clientIP(header http.Header) netip.Addr {
	if v := header.Get("X-Forwarded-For"); v != "" {
		// 取第一段（最远的 client，链式 proxy 时是真实源）
		first := v
		if i := strings.IndexByte(v, ','); i > 0 {
			first = v[:i]
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
			return a
		}
	}
	if v := header.Get("X-Real-IP"); v != "" {
		if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
			return a
		}
	}
	return netip.Addr{}
}

// userAgent 取 User-Agent header；缺失时返空串（Login 流程兼容）。
func userAgent(header http.Header) string {
	return header.Get("User-Agent")
}
