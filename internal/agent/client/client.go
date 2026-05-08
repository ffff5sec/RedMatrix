// Package client 提供 Agent 用的两个 ConnectRPC client 工厂。
//
//   - PublicTenancy(serverURL) → 走普通 HTTPS / dev HTTP；用于 Redeem
//     RegistrationToken（首启即弃；不带 client cert）。
//   - MTLSNodeAgent(serverURL, enroll) → mTLS（client cert + 校 server cert
//     against enrolled CA）；用于周期 Heartbeat。
//
// 设计要点：
//   - serverURL 留给 caller 解析；本包只做 client 装配
//   - 测试可通过 WithHTTPClient 注入 stub transport（绕开真 TCP）
package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
)

// PublicTenancy 构造可调 RedeemRegistrationToken 的客户端。
//
// 不需要客户端证书；用 http.DefaultClient（或 caller 注入的）。dev 场景下
// serverURL 也可以是 http://（连同上面注释；生产必须 https://）。
func PublicTenancy(serverURL string, opts ...Option) (tenancyv1connect.TenancyServiceClient, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return nil, errors.New("agent client: server URL 不能为空")
	}
	cfg := newConfig(opts...)
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return tenancyv1connect.NewTenancyServiceClient(httpClient, serverURL), nil
}

// MTLSNodeAgent 构造可调 Heartbeat 的 mTLS 客户端。
//
// enroll.CertPEM/KeyPEM 充当 client identity；enroll.CACertPEM 校 server cert。
// TLS 1.3 only；ServerName 为空时由 connect-go 从 URL 推。
func MTLSNodeAgent(serverURL string, enroll *store.Enrollment, opts ...Option) (tenancyv1connect.NodeAgentServiceClient, error) {
	serverURL = strings.TrimSpace(serverURL)
	if serverURL == "" {
		return nil, errors.New("agent client: node-agent URL 不能为空")
	}
	if enroll == nil {
		return nil, errors.New("agent client: enrollment is nil")
	}

	tlsCfg, err := mtlsConfig(enroll)
	if err != nil {
		return nil, err
	}

	cfg := newConfig(opts...)
	if cfg.serverName != "" {
		tlsCfg.ServerName = cfg.serverName
	}

	// connect-go 在 HTTPS 路径下自动用 http2；显式给 transport 让 TLS 配生效。
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
		},
	}
	return tenancyv1connect.NewNodeAgentServiceClient(
		httpClient, serverURL, connect.WithGRPC(),
	), nil
}

// mtlsConfig 根据 enrollment 构造 client mTLS tls.Config。
func mtlsConfig(e *store.Enrollment) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(e.CertPEM, e.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("agent client: 解析 cert/key: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(e.CACertPEM) {
		return nil, errors.New("agent client: CA PEM 解析失败")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Option 调整 client 工厂行为。
type Option func(*config)

type config struct {
	httpClient *http.Client
	serverName string
}

func newConfig(opts ...Option) *config {
	c := &config{}
	for _, o := range opts {
		o(c)
	}
	return c
}

// WithHTTPClient 注 caller 自备 http.Client（测试时塞 stub transport）。
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *config) { cfg.httpClient = c }
}

// WithServerName 覆盖 mTLS ServerName SAN 校验目标。生产留空让 connect-go
// 从 URL 推；自签 cert dev 时显式填实际 CN（如 "localhost"）。
func WithServerName(s string) Option {
	return func(cfg *config) { cfg.serverName = s }
}
