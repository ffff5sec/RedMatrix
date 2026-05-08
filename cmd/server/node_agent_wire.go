// node_agent_wire.go 装配 mTLS-only 的 NodeAgentService 端点（PR-T4-D3）。
//
// 与主 HTTP server 分离的原因：
//   - 不同认证模式：主 HTTP 走 cookie/JWT；本端点要求 client cert
//   - 不同攻击面：开放给所有 Agent 走公网，监控 / rate limit 策略不同
//   - 解耦端口：运维可在防火墙独立隔离
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/storage/pg"
	"github.com/ffff5sec/RedMatrix/internal/tenancy"
	tenancyhandler "github.com/ffff5sec/RedMatrix/internal/tenancy/handler"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/mtls"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
	tenancyrepo "github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// nodeAgentServer 包装 mTLS http.Server + listener；空指针表示未启用。
type nodeAgentServer struct {
	srv *http.Server
}

// startNodeAgentServer 启动 mTLS-only http.Server 在 addr 上。
//
// addr 空 → 返 (nil, nil) 跳过；caller 在 shutdown 时无需关。
//
// TLS 配置：
//   - 服务端身份：ca 现签一份 server leaf（30d 有效；重启自动轮换）
//   - ClientAuth = RequireAndVerifyClientCert
//   - ClientCAs = 单 CA 池
func startNodeAgentServer(
	ctx context.Context,
	logger *log.Logger,
	pool *pg.Pool,
	svc tenancy.Service,
	ca *pki.CA,
	addr string,
) (*nodeAgentServer, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		logger.Info("node_agent server skipped (PUBLIC_GRPC_ADDR 未配)")
		return nil, nil
	}
	if pool == nil || pool.App == nil {
		return nil, errx.New(errx.ErrInternal, "startNodeAgentServer: pool 不能为 nil")
	}
	if svc == nil {
		return nil, errx.New(errx.ErrInternal, "startNodeAgentServer: svc 不能为 nil")
	}
	if ca == nil || ca.Cert == nil || ca.Key == nil {
		return nil, errx.New(errx.ErrInternal, "startNodeAgentServer: ca 不能为 nil")
	}

	// === 1. 装中间件 + handler → mux ===
	certs := tenancyrepo.NewNodeCertificatePG(pool.App)
	mw, err := mtls.NewMiddleware(certs, logger)
	if err != nil {
		return nil, err
	}
	h, err := tenancyhandler.NewNodeAgent(svc)
	if err != nil {
		return nil, err
	}
	path, raw := tenancyv1connect.NewNodeAgentServiceHandler(h)
	mux := http.NewServeMux()
	mux.Handle(path, mw.Wrap(raw))

	// === 2. 签 server leaf ===
	leafKey, err := pki.NewLeafKey()
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "startNodeAgentServer: 生成 server key 失败")
	}
	hostnames, ips := splitHostnames(addr)
	cn := "redmatrix-node-agent"
	if len(hostnames) > 0 && hostnames[0] != "" {
		cn = hostnames[0]
	}
	leaf, leafCertPEM, err := ca.SignLeaf(leafKey.Public(), pki.SignLeafOptions{
		CommonName: cn,
		DNSNames:   hostnames,
		IPs:        ips,
		Usage:      pki.LeafUsageServer,
		Validity:   pki.DefaultLeafValidity,
		Now:        time.Now(),
	})
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "startNodeAgentServer: 签 server leaf 失败")
	}
	leafKeyPEM, err := pki.MarshalLeafKeyPEM(leafKey)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "startNodeAgentServer: marshal leaf key 失败")
	}
	tlsCert, err := tls.X509KeyPair(leafCertPEM, leafKeyPEM)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "startNodeAgentServer: 拼 tls.Cert 失败")
	}

	// === 3. ClientCAs 池 + listener ===
	pool509 := x509.NewCertPool()
	pool509.AddCert(ca.Cert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    pool509,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "startNodeAgentServer: listen 失败").
			WithFields("addr", addr)
	}

	srv := &http.Server{
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: defaultHTTPReadHeaderTimeout,
	}

	go func() {
		if err := srv.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.LogError(ctx, "node_agent server crashed", err)
		}
	}()
	logger.Info("node_agent mTLS server listening",
		"addr", addr,
		"path", path,
		"server_cert_expires_at", leaf.NotAfter.UTC().Format(time.RFC3339),
	)

	return &nodeAgentServer{srv: srv}, nil
}

// splitHostnames 把 addr "host:port" 拆出可用作 SAN 的 hosts/ips。
//
// 0.0.0.0 / "" / "::" → 默认 SAN（127.0.0.1 + ::1 + localhost）；
// 字面量 IP → IPs；否则 → DNSNames。
func splitHostnames(addr string) (dns []string, ips []net.IP) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	}
	if ip := net.ParseIP(host); ip != nil {
		return nil, []net.IP{ip}
	}
	return []string{host}, nil
}

// shutdown 优雅关停（带 timeout）。可重复调用；nil 接收者无操作。
func (s *nodeAgentServer) shutdown(timeout time.Duration) error {
	if s == nil || s.srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		return fmt.Errorf("node_agent shutdown: %w", err)
	}
	return nil
}
