// Package artifact 是 scan 模块的大文件结果落地层（PR-S16）。
//
// 设计：plugin 产生大文件（截图 / pcap / raw HTML / nuclei JSON）时，
// agent 不通过 mTLS RPC 中转，而是：
//
//  1. 申请 server 签的 presigned PUT URL（NodeAgentService.CreateArtifactUploadURL）
//  2. agent 直接 HTTP PUT 到 MinIO
//  3. agent 上报 scan_result 时把 artifact_key 字段写进 data
//  4. 前端列结果时检测 artifact_key → 调 ScanService.GetArtifactDownloadURL
//     拿 presigned GET → 浏览器跳转下载
//
// 好处：不下发 MinIO 凭证给 agent；不走 mTLS 通道传大文件；签名 URL TTL
// 短（默认 10min）限制泄露损失。
//
// bucket：MVP 复用 PR-S0 预设的 redmatrix-response-bodies（含 30d 生命周期）。
// 未来按 content_type 路由：image/png → redmatrix-screenshots。
package artifact

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	rmminio "github.com/ffff5sec/RedMatrix/internal/storage/minio"
)

// DefaultBucket MVP 默认 bucket（30d lifecycle，PR-S0 预设）。
const DefaultBucket = "redmatrix-response-bodies"

// DefaultURLTTL 预签名 URL 有效期。
const DefaultURLTTL = 10 * time.Minute

// Store 大文件 artifact 持久化层。
type Store interface {
	// MakeKey 给定 tenant + task hint 生成唯一 key（tenant/<uuid>[<ext>]）。
	MakeKey(tenantID, ext string) string

	// PresignPutURL 签 PUT URL；caller（agent）直接 HTTP PUT 到此 URL 上传。
	PresignPutURL(ctx context.Context, key string, ttl time.Duration) (string, error)

	// PresignGetURL 签 GET URL；caller（前端）直接跳 URL 下载。
	PresignGetURL(ctx context.Context, key string, ttl time.Duration) (string, error)
}

// MinIOStore minio-go 实现。
type MinIOStore struct {
	client *rmminio.Client
	bucket string
}

// New 构造。
func New(client *rmminio.Client, bucket string) (*MinIOStore, error) {
	if client == nil || client.Client == nil {
		return nil, errx.New(errx.ErrInternal, "artifact.New: minio client 不能为 nil")
	}
	if strings.TrimSpace(bucket) == "" {
		bucket = DefaultBucket
	}
	return &MinIOStore{client: client, bucket: bucket}, nil
}

// MakeKey 生成 tenantID/<uuid>[<ext>] 形式 key。ext 含点（".png"）才使用。
func (s *MinIOStore) MakeKey(tenantID, ext string) string {
	tenant := strings.TrimSpace(tenantID)
	if tenant == "" {
		tenant = "unscoped"
	}
	id := uuid.NewString()
	if ext != "" && !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	return tenant + "/" + id + ext
}

// PresignPutURL Presign 一个 PUT；TTL≤0 用默认。
func (s *MinIOStore) PresignPutURL(ctx context.Context, key string, ttl time.Duration) (string, error) {
	if s == nil || s.client == nil {
		return "", errx.New(errx.ErrInternal, "artifact.PresignPutURL: nil store")
	}
	if strings.TrimSpace(key) == "" {
		return "", errx.New(errx.ErrInvalidInput, "artifact.PresignPutURL: 空 key")
	}
	if ttl <= 0 {
		ttl = DefaultURLTTL
	}
	u, err := s.client.PresignedPutObject(ctx, s.bucket, key, ttl)
	if err != nil {
		return "", errx.Wrap(errx.ErrUpstreamTimeout, err, "artifact: presign put")
	}
	return u.String(), nil
}

// PresignGetURL 同上，GET。
func (s *MinIOStore) PresignGetURL(ctx context.Context, key string, ttl time.Duration) (string, error) {
	if s == nil || s.client == nil {
		return "", errx.New(errx.ErrInternal, "artifact.PresignGetURL: nil store")
	}
	if strings.TrimSpace(key) == "" {
		return "", errx.New(errx.ErrInvalidInput, "artifact.PresignGetURL: 空 key")
	}
	if ttl <= 0 {
		ttl = DefaultURLTTL
	}
	u, err := s.client.PresignedGetObject(ctx, s.bucket, key, ttl, nil)
	if err != nil {
		return "", errx.Wrap(errx.ErrUpstreamTimeout, err, "artifact: presign get")
	}
	return u.String(), nil
}

// ErrKeyTraversal artifact key 包含 ../ 等路径穿越字符；server 端在签名前应拒。
var ErrKeyTraversal = errors.New("artifact: key contains path traversal")

// ValidateKey 校验 key 形态：非空 + 不含 ".." 段 + 不以 "/" 开头 + 不超 1024。
func ValidateKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return errx.New(errx.ErrInvalidInput, "artifact.key 不能为空")
	}
	if len(key) > 1024 {
		return errx.New(errx.ErrInvalidInput, "artifact.key 超长")
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return errx.New(errx.ErrInvalidInput, ErrKeyTraversal.Error())
	}
	// minio key 字符集 OK；ASCII 控制字符拒
	for _, c := range key {
		if c < 0x20 || c == 0x7f {
			return errx.New(errx.ErrInvalidInput, "artifact.key 含控制字符")
		}
	}
	return nil
}

// 用于解耦的接口断言：编译期保证 MinIOStore 满足 Store。
var _ Store = (*MinIOStore)(nil)

// minio 包用于在测试中创建 fake；运行时 New 路径不直接 import 公开包。
var _ = minio.PutObjectOptions{}
