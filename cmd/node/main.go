// Command redmatrix-node 是扫描节点 Agent 的入口（PR-T4-D4 起进入心跳期）。
//
// 启动序列（详见 LLD 13-scan §节点端 / 40-deployment-detail §3）：
//  1. 解析 flag/env：server-url / node-agent-url / data-dir / token / node-name
//  2. store.Load → ErrNotEnrolled → 走 Redeem 流程并持久；否则跳过
//  3. 用持久化的 cert/key/CA 构 mTLS client
//  4. 进入 Heartbeat 循环（心跳间隔 server 下发，默认 30s ± 10% jitter）
//
// 设计取舍：
//   - 不支持 cert 自动续期（cert 过期 → Agent 崩，运维 Revoke 旧 cert + 重 enroll）
//   - 不支持热重载 token；首启不带 token + 未 enroll → 直接退出
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ffff5sec/RedMatrix/internal/agent/client"
	"github.com/ffff5sec/RedMatrix/internal/agent/enroll"
	"github.com/ffff5sec/RedMatrix/internal/agent/heartbeat"
	"github.com/ffff5sec/RedMatrix/internal/agent/store"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/version"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "redmatrix-node: %v\n", err)
		os.Exit(1)
	}
}

// agentOptions 是 main 解析后的全部配置。
type agentOptions struct {
	serverURL     string // 公网 ConnectRPC URL（Redeem 用）；e.g. https://api.example.com
	nodeAgentURL  string // mTLS NodeAgent URL；e.g. https://api.example.com:9090
	dataDir       string // enrollment 落盘目录
	token         string // 首启 RegistrationToken plaintext（已 enroll 时忽略）
	nodeName      string // Agent 自报名（租户内唯一）
	mtlsServerSAN string // 自签 dev cert 时显式 SAN（如 "localhost"）
	printVersion  bool
}

func parseFlags(args []string) (*agentOptions, error) {
	o := &agentOptions{}
	fs := flag.NewFlagSet("redmatrix-node", flag.ContinueOnError)
	fs.StringVar(&o.serverURL, "server-url", os.Getenv("REDMATRIX_SERVER_URL"),
		"公网 RPC 入口（Redeem 用）；env REDMATRIX_SERVER_URL")
	fs.StringVar(&o.nodeAgentURL, "node-agent-url", os.Getenv("REDMATRIX_NODE_AGENT_URL"),
		"mTLS NodeAgent 入口（Heartbeat 用）；env REDMATRIX_NODE_AGENT_URL")
	fs.StringVar(&o.dataDir, "data-dir", envOr("REDMATRIX_NODE_DATA_DIR", "data/node"),
		"enrollment 持久目录；env REDMATRIX_NODE_DATA_DIR")
	fs.StringVar(&o.token, "token", os.Getenv("REDMATRIX_NODE_TOKEN"),
		"首启 RegistrationToken plaintext；env REDMATRIX_NODE_TOKEN")
	fs.StringVar(&o.nodeName, "node-name", os.Getenv("REDMATRIX_NODE_NAME"),
		"Agent 自报名（租户内唯一）；env REDMATRIX_NODE_NAME")
	fs.StringVar(&o.mtlsServerSAN, "mtls-server-name", os.Getenv("REDMATRIX_MTLS_SERVER_NAME"),
		"mTLS ServerName 校验目标（自签 dev 用，e.g. localhost）；env REDMATRIX_MTLS_SERVER_NAME")
	fs.BoolVar(&o.printVersion, "version", false, "打印版本并退出")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	if o.printVersion {
		fmt.Fprintln(stdout, version.String())
		return nil
	}
	if err := validateOptions(o); err != nil {
		return err
	}

	logger, err := log.New(log.Config{Level: "info", Format: "text"})
	if err != nil {
		return fmt.Errorf("init logger: %w", err)
	}
	logger.Info("redmatrix-node starting",
		"version", version.Version,
		"server_url", o.serverURL,
		"node_agent_url", o.nodeAgentURL,
		"data_dir", o.dataDir,
	)

	st, err := store.New(o.dataDir)
	if err != nil {
		return err
	}
	pubClient, err := client.PublicTenancy(o.serverURL)
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// === 1. enroll（已 enroll 时直接跳过 Redeem）===
	en, err := (&enroll.Enroller{Store: st, Client: pubClient}).Ensure(ctx, enroll.Request{
		Plaintext: o.token,
		NodeName:  o.nodeName,
		Version:   version.Version,
	})
	if err != nil {
		return err
	}
	logger.Info("agent enrolled", "node_id", en.NodeID)

	// === 2. mTLS client + heartbeat loop ===
	mtlsOpts := []client.Option{}
	if o.mtlsServerSAN != "" {
		mtlsOpts = append(mtlsOpts, client.WithServerName(o.mtlsServerSAN))
	}
	naClient, err := client.MTLSNodeAgent(o.nodeAgentURL, en, mtlsOpts...)
	if err != nil {
		return err
	}

	hl := &heartbeat.Loop{
		Client:  naClient,
		Version: version.Version,
		Logger:  logger,
	}
	if err := hl.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(stderr, "redmatrix-node: heartbeat exited: %v\n", err)
		return err
	}
	logger.Info("redmatrix-node shutting down")
	return nil
}

// validateOptions 拒绝必填项缺失；node-agent-url 留空 → 用 server-url（同主机不同端口
// 由运维选；MVP 不做自动推导）。
func validateOptions(o *agentOptions) error {
	if strings.TrimSpace(o.serverURL) == "" {
		return errors.New("缺 -server-url / REDMATRIX_SERVER_URL")
	}
	if strings.TrimSpace(o.nodeAgentURL) == "" {
		return errors.New("缺 -node-agent-url / REDMATRIX_NODE_AGENT_URL")
	}
	return nil
}

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}
