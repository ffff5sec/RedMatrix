// Package minio 包装 minio-go/v7 提供 RedMatrix 后端 S3 兼容对象存储客户端。
//
// 设计原则（docs/LLD/01-database-schema.md §3.4 + 40 §4.4 + 40 §9.6）：
//   - 内网 endpoint（MinIO_ENDPOINT，例 "minio:9000"，UseSSL=false）
//   - 公网 endpoint（MINIO_PUBLIC_ENDPOINT，节点拉插件 / UI 预签名下载，UseSSL=true）
//     公网 client 由调用方按需另开（本包同样支持）
//   - 启动期 9 bucket 存在性校验 → BOOTSTRAP_STORAGE_MISSING
//   - WORM compliance / governance 配置由 docker-compose minio-bootstrap job 设
//     （Server 不主动改 bucket 锁定策略；Phase 2 添加 verify 钩子）
package minio

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// RequiredBuckets 启动期必须存在的 9 个 bucket，与 01 §3.4 / 40 §4.4 严格一致。
var RequiredBuckets = []string{
	"redmatrix-plugins",          // 插件二进制 / YAML POC（节点拉取）
	"redmatrix-screenshots",      // 任务截图（生命周期 30d）
	"redmatrix-response-bodies",  // 大响应体（30d）
	"redmatrix-reports",          // 业务报告导出（30d）
	"redmatrix-audit-archive",    // 审计归档 WORM 90d compliance
	"redmatrix-es-snapshots",     // ES 快照
	"redmatrix-logs",             // Loki 后端
	"redmatrix-backups",          // PG dump 加密备份 governance 30d
	"redmatrix-avatars",          // 用户头像
}

// Config MinIO 客户端配置。
type Config struct {
	Endpoint  string // "host:port"（不含 scheme；UseSSL 决定协议）
	AccessKey string
	SecretKey string
	UseSSL    bool   // 内网通常 false；公网走 Caddy 透传 https 时 true
	Region    string // 可选；默认 "us-east-1"
}

const defaultRegion = "us-east-1"

// Client 包装 *minio.Client。Embed 让调用方直接走原生 SDK。
type Client struct {
	*miniogo.Client
}

// Open 解析 endpoint 构造 client。不主动建连（minio-go 是 lazy）。
//
//   - Endpoint / AccessKey / SecretKey 必填
//   - Endpoint 不应含 scheme（"http://"），含则报 BOOTSTRAP_CONFIG_INVALID
func Open(_ context.Context, cfg Config) (*Client, error) {
	if cfg.Endpoint == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"MinIO endpoint 必填").WithFields("var", "MINIO_ENDPOINT")
	}
	if strings.Contains(cfg.Endpoint, "://") {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"MinIO endpoint 不应含 scheme（用 host:port，scheme 由 UseSSL 决定）").
			WithFields("var", "MINIO_ENDPOINT", "got", cfg.Endpoint)
	}
	if cfg.AccessKey == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"MINIO_ACCESS_KEY 必填").WithFields("var", "MINIO_ACCESS_KEY")
	}
	if cfg.SecretKey == "" {
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"MINIO_SECRET_KEY 必填").WithFields("var", "MINIO_SECRET_KEY")
	}
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}

	cli, err := miniogo.New(cfg.Endpoint, &miniogo.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapConfigInvalid, err, "MinIO client 构造失败")
	}
	return &Client{Client: cli}, nil
}

// Ping 通过 ListBuckets 探活（同时验证 access key 有效）。
//
// 失败 → BOOTSTRAP_DB_UNREACHABLE。
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.Client == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "MinIO client 未初始化")
	}
	if _, err := c.Client.ListBuckets(ctx); err != nil {
		return errx.Wrap(errx.ErrBootstrapDBUnreachable, err, "MinIO ListBuckets 失败")
	}
	return nil
}

// VerifyBuckets 校验所有给定 bucket 存在；缺失返回 BOOTSTRAP_STORAGE_MISSING（含 bucket 名）。
//
// 生产路径：cmd/server boot 用 RequiredBuckets 调用，缺失即 fail-fast。
// bucket 创建由 docker-compose minio-bootstrap job 完成（40 §4.4），Server 仅校验。
func (c *Client) VerifyBuckets(ctx context.Context, buckets []string) error {
	if c == nil || c.Client == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "MinIO client 未初始化")
	}
	for _, name := range buckets {
		ok, err := c.Client.BucketExists(ctx, name)
		if err != nil {
			return errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
				"MinIO BucketExists 失败").WithFields("bucket", name)
		}
		if !ok {
			return errx.New(errx.ErrBootstrapStorageMissing,
				fmt.Sprintf("MinIO 必需 bucket 不存在: %s（运维需先执行 minio-bootstrap）", name)).
				WithFields("bucket", name)
		}
	}
	return nil
}

// EnsureBuckets 创建任何缺失的 bucket（dev / 测试用）。生产仅 VerifyBuckets。
//
// 不设置 WORM / 生命周期（这些由 minio-bootstrap 脚本管理）。
func (c *Client) EnsureBuckets(ctx context.Context, buckets []string, region string) error {
	if c == nil || c.Client == nil {
		return errx.New(errx.ErrBootstrapDBUnreachable, "MinIO client 未初始化")
	}
	if region == "" {
		region = defaultRegion
	}
	for _, name := range buckets {
		ok, err := c.Client.BucketExists(ctx, name)
		if err != nil {
			return errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
				"MinIO BucketExists 失败").WithFields("bucket", name)
		}
		if ok {
			continue
		}
		if err := c.Client.MakeBucket(ctx, name, miniogo.MakeBucketOptions{Region: region}); err != nil {
			// MakeBucket 可能因并发竞态返回 BucketAlreadyOwnedByYou；忽略。
			if !isAlreadyOwned(err) {
				return errx.Wrap(errx.ErrBootstrapDBUnreachable, err,
					"MinIO MakeBucket 失败").WithFields("bucket", name)
			}
		}
	}
	return nil
}

func isAlreadyOwned(err error) bool {
	if err == nil {
		return false
	}
	var resp miniogo.ErrorResponse
	if errors.As(err, &resp) {
		return resp.Code == "BucketAlreadyOwnedByYou" || resp.Code == "BucketAlreadyExists"
	}
	return strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") ||
		strings.Contains(err.Error(), "BucketAlreadyExists")
}

// Close 是占位（minio-go 客户端无显式 Close；transport 由 GC 回收）。
func (c *Client) Close() error { return nil }

// Sanitize 返回 endpoint:accessKey 形式的脱敏字串（accessKey 截短）；
// SecretKey 永不出现在返回值。日志安全输出用。
func Sanitize(endpoint, accessKey string) string {
	if endpoint == "" && accessKey == "" {
		return ""
	}
	masked := maskAccessKey(accessKey)
	if endpoint == "" {
		return masked
	}
	return endpoint + " (key=" + masked + ")"
}

// maskAccessKey 把 access key 截短为 "first4***last4"（短的全脱）。
func maskAccessKey(k string) string {
	if k == "" {
		return ""
	}
	if len(k) <= 8 {
		return strings.Repeat("*", len(k))
	}
	return k[:4] + "***" + k[len(k)-4:]
}

// EndpointHTTPURL 把 host:port + UseSSL 拼成完整 URL（仅用于日志展示，不参与连接）。
func EndpointHTTPURL(endpoint string, useSSL bool) string {
	if endpoint == "" {
		return ""
	}
	scheme := "http"
	if useSSL {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: endpoint}
	return u.String()
}

// PingTimeout 是 ListBuckets 默认上下文超时建议（10s，调用方如需可自定义 ctx）。
const PingTimeout = 10 * time.Second
