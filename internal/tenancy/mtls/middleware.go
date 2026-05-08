// Package mtls 实现 Agent 入口的客户端证书认证中间件。
//
// 流程（PR-T4-D3）：
//  1. *http.Server 配 tls.Config{ClientAuth: RequireAndVerifyClientCert,
//     ClientCAs: 单 CA 池}（在 cmd/server 里组装）
//  2. 入站请求被本中间件拦下：从 r.TLS.PeerCertificates[0] 算 SHA-256
//  3. NodeCertificateRepository.GetByFingerprint → 拿到 *NodeCertificate
//  4. cert.IsValid(now) 校验未撤未过期
//  5. 通过 → ctx 注 node_id；handler 走 svc.Heartbeat
//
// 失败一律返 401 + 简短日志，不向 Agent 暴露细节（防指纹枚举 node_id）。
package mtls

import (
	"errors"
	"net/http"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// Middleware 把 mTLS peer cert 反查 → node_id 注 ctx 的 net/http middleware。
//
// 字段：
//   - certs：cert 反查
//   - logger：失败原因仅日志侧记录（不回 client）
//   - now：测试时可注 fake clock
type Middleware struct {
	certs  repo.NodeCertificateRepository
	logger *log.Logger
	now    func() time.Time
}

// NewMiddleware 构造。certs 必填；logger 可空；now 默认 time.Now。
func NewMiddleware(certs repo.NodeCertificateRepository, logger *log.Logger) (*Middleware, error) {
	if certs == nil {
		return nil, errx.New(errx.ErrInternal, "mtls.NewMiddleware: certs 不能为 nil")
	}
	return &Middleware{certs: certs, logger: logger, now: time.Now}, nil
}

// Wrap 把 next 包成 mTLS-认证后的 handler。请求未携带客户端证书 / 证书无效 →
// 401 + 空响应；通过则注 ctx 进 next。
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			m.deny(w, r, "no_peer_cert", nil)
			return
		}
		peer := r.TLS.PeerCertificates[0]
		fp := pki.Fingerprint(peer)

		cert, err := m.certs.GetByFingerprint(r.Context(), fp)
		if err != nil {
			m.deny(w, r, "cert_not_found", err)
			return
		}

		if !cert.IsValid(m.now()) {
			m.deny(w, r, "cert_invalid", nil)
			return
		}

		ctx := ctxmeta.WithNodeID(r.Context(), cert.NodeID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deny 写 401，日志记原因，永不向 client 暴露细节。
func (m *Middleware) deny(w http.ResponseWriter, r *http.Request, reason string, cause error) {
	if m.logger != nil {
		fields := []any{"reason", reason, "remote", r.RemoteAddr}
		if cause != nil {
			fields = append(fields, "cause", causeSummary(cause))
		}
		m.logger.Warn("mtls auth denied", fields...)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}

// causeSummary 抽 errx code 字符串；非 errx 错返通用占位。
func causeSummary(err error) string {
	if err == nil {
		return ""
	}
	if c, ok := errx.GetCode(err); ok {
		return string(c)
	}
	if errors.Is(err, http.ErrAbortHandler) {
		return "abort"
	}
	return "unknown"
}
