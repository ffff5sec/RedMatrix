// Package pluginpkg 插件包分发 service（PR-S28）。
package pluginpkg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	miniogo "github.com/minio/minio-go/v7"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/repo"
)

// BucketName 存插件二进制的 MinIO bucket。
const BucketName = "redmatrix-plugins"

// DefaultDownloadTTL presigned GET URL 默认有效期。
const DefaultDownloadTTL = 15 * time.Minute

// MaxUploadSize 单个插件包上限（避 OOM）。
const MaxUploadSize = 200 * 1024 * 1024 // 200 MiB

// MinIOClient 仅依赖最小接口；测试可 stub。
type MinIOClient interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts miniogo.PutObjectOptions) (miniogo.UploadInfo, error)
	PresignedGetObject(ctx context.Context, bucket, object string, expires time.Duration, params url.Values) (*url.URL, error)
	RemoveObject(ctx context.Context, bucket, object string, opts miniogo.RemoveObjectOptions) error
}

// Service plugin 模块对外接口。
type Service interface {
	UploadPackage(ctx context.Context, req UploadRequest) (*domain.PluginPackage, error)
	ListPackages(ctx context.Context, req ListRequest) (*ListResult, error)
	GetPackage(ctx context.Context, id string) (*domain.PluginPackage, error)
	GetLatestVersion(ctx context.Context, slug, platform string) (*domain.PluginPackage, error)
	GetDownloadURL(ctx context.Context, id string) (downloadURL string, expiresAt time.Time, err error)
	SetActive(ctx context.Context, id string, active bool) error
	DeprecatePackage(ctx context.Context, id string) error

	// 公钥分发
	ListSigningKeys(ctx context.Context) ([]*domain.SigningKey, error)
	RegisterSigningKey(ctx context.Context, key *domain.SigningKey) (*domain.SigningKey, error)
	RevokeSigningKey(ctx context.Context, keyID string) error
}

// UploadRequest 单文件上传入参。Binary 是原始字节（小文件 OK；大文件后续走 stream）。
type UploadRequest struct {
	Slug        string
	Version     string
	Platform    string
	Description string
	Binary      []byte
	UploaderID  string
}

// ListRequest 列入参。
type ListRequest struct {
	Slug     string
	Platform string
	Active   *bool
	Page     int
	PageSize int
}

// ListResult 分页。
type ListResult struct {
	Packages []*domain.PluginPackage
	Total    int
	Page     int
	PageSize int
}

// Deps service 依赖。
type Deps struct {
	Packages       repo.PluginRepository
	SigningKeys    repo.SigningKeyRepository
	MinIO          MinIOClient
	SigningKeyID   string             // 当前签名 key 的短 ID（与 plugin_signing_keys.key_id 匹配）
	SigningPrivate ed25519.PrivateKey // 私钥（从 env 注入）；nil = 上传失败
}

type service struct {
	packages       repo.PluginRepository
	keys           repo.SigningKeyRepository
	minio          MinIOClient
	signingKeyID   string
	signingPrivate ed25519.PrivateKey
	now            func() time.Time
}

// New 构造 Service。
func New(d Deps) (Service, error) {
	if d.Packages == nil || d.SigningKeys == nil {
		return nil, errx.New(errx.ErrInternal, "pluginpkg.New: repos 不能为空")
	}
	if d.MinIO == nil {
		return nil, errx.New(errx.ErrInternal, "pluginpkg.New: MinIO client 不能为空")
	}
	return &service{
		packages:       d.Packages,
		keys:           d.SigningKeys,
		minio:          d.MinIO,
		signingKeyID:   d.SigningKeyID,
		signingPrivate: d.SigningPrivate,
		now:            time.Now,
	}, nil
}

// === Upload ===

// UploadPackage 主路径：算 sha256 → 签 → MinIO put → INSERT。
//
// 任何一步失败，原子回滚（已上传到 MinIO 的 object 调 RemoveObject 清理）。
func (s *service) UploadPackage(ctx context.Context, req UploadRequest) (*domain.PluginPackage, error) {
	if s.signingPrivate == nil || s.signingKeyID == "" {
		return nil, errx.New(errx.ErrPluginInstallationFailed,
			"server 未配置 PLUGIN_SIGNING_KEY；无法上传插件")
	}
	if len(req.Binary) == 0 {
		return nil, errx.New(errx.ErrPluginInvalidFormat, "binary 为空")
	}
	if len(req.Binary) > MaxUploadSize {
		return nil, errx.New(errx.ErrPluginInvalidFormat,
			fmt.Sprintf("binary 超过 %d 字节上限", MaxUploadSize))
	}
	if !domain.Platform(req.Platform).Valid() {
		return nil, errx.New(errx.ErrPluginPlatformMismatch,
			"platform 不合法").WithFields("got", req.Platform)
	}

	sha := domain.ComputeSHA256Hex(req.Binary)
	sig := domain.SignSHA256(s.signingPrivate, sha)

	// MinIO key：plugins/<slug>/<version>/<platform>/binary
	objectKey := fmt.Sprintf("plugins/%s/%s/%s/binary",
		safeSlug(req.Slug), safeSlug(req.Version), safeSlug(req.Platform))

	// PutObject
	_, err := s.minio.PutObject(ctx, BucketName, objectKey,
		bytes.NewReader(req.Binary), int64(len(req.Binary)),
		miniogo.PutObjectOptions{
			ContentType: "application/octet-stream",
			UserMetadata: map[string]string{
				"slug":     req.Slug,
				"version":  req.Version,
				"platform": req.Platform,
				"sha256":   sha,
			},
		})
	if err != nil {
		return nil, errx.Wrap(errx.ErrPluginInstallationFailed, err, "MinIO PutObject 失败")
	}

	pkg := &domain.PluginPackage{
		Slug:         req.Slug,
		Version:      req.Version,
		Platform:     domain.Platform(req.Platform),
		ArtifactKey:  objectKey,
		SHA256:       sha,
		Signature:    sig,
		SigningKeyID: s.signingKeyID,
		//nolint:gosec // len(req.Binary) ≤ MaxUploadSize = 200MiB；不溢出
		SizeBytes:   int64(len(req.Binary)),
		Description: req.Description,
		IsActive:    true,
		UploadedBy:  req.UploaderID,
	}
	if err := s.packages.Insert(ctx, pkg); err != nil {
		// 回滚 MinIO object
		_ = s.minio.RemoveObject(ctx, BucketName, objectKey, miniogo.RemoveObjectOptions{})
		return nil, err
	}
	return pkg, nil
}

// safeSlug 防 MinIO key path 注入。
func safeSlug(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "..", "_")
	return s
}

// === List / Get ===

func (s *service) ListPackages(ctx context.Context, req ListRequest) (*ListResult, error) {
	out, total, err := s.packages.List(ctx, repo.PluginFilter{
		Slug:     req.Slug,
		Platform: req.Platform,
		Active:   req.Active,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListResult{
		Packages: out, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

func (s *service) GetPackage(ctx context.Context, id string) (*domain.PluginPackage, error) {
	return s.packages.GetByID(ctx, id)
}

func (s *service) GetLatestVersion(ctx context.Context, slug, platform string) (*domain.PluginPackage, error) {
	if !domain.Platform(platform).Valid() {
		return nil, errx.New(errx.ErrPluginPlatformMismatch, "platform 不合法").
			WithFields("got", platform)
	}
	return s.packages.GetLatestActive(ctx, slug, platform)
}

// GetDownloadURL 生成 presigned GET URL（TTL 15min）。
func (s *service) GetDownloadURL(ctx context.Context, id string) (string, time.Time, error) {
	pkg, err := s.packages.GetByID(ctx, id)
	if err != nil {
		return "", time.Time{}, err
	}
	if pkg.IsDeprecated() {
		return "", time.Time{}, errx.New(errx.ErrPluginInactive, "插件已 deprecated").WithFields("id", id)
	}
	if !pkg.IsActive {
		return "", time.Time{}, errx.New(errx.ErrPluginInactive, "插件已禁用").WithFields("id", id)
	}
	u, err := s.minio.PresignedGetObject(ctx, BucketName, pkg.ArtifactKey, DefaultDownloadTTL, nil)
	if err != nil {
		return "", time.Time{}, errx.Wrap(errx.ErrPluginDownload, err, "presigned GET 失败")
	}
	return u.String(), s.now().Add(DefaultDownloadTTL), nil
}

// === Active / Deprecate ===

func (s *service) SetActive(ctx context.Context, id string, active bool) error {
	return s.packages.UpdateActive(ctx, id, active)
}

func (s *service) DeprecatePackage(ctx context.Context, id string) error {
	return s.packages.Deprecate(ctx, id)
}

// === Signing keys ===

func (s *service) ListSigningKeys(ctx context.Context) ([]*domain.SigningKey, error) {
	return s.keys.ListActive(ctx)
}

func (s *service) RegisterSigningKey(ctx context.Context, key *domain.SigningKey) (*domain.SigningKey, error) {
	if err := s.keys.Insert(ctx, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *service) RevokeSigningKey(ctx context.Context, keyID string) error {
	return s.keys.Revoke(ctx, keyID)
}

// === 启动期：从 env 加载 / 自动注册当前签名 key ===

// LoadPrivateKeyFromBase64 从 base64 字串解码 ed25519 私钥。
func LoadPrivateKeyFromBase64(b64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errx.New(errx.ErrPluginInvalidFormat, "私钥不是合法 base64")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errx.New(errx.ErrPluginInvalidFormat,
			fmt.Sprintf("私钥长度错（got=%d want=%d）", len(raw), ed25519.PrivateKeySize))
	}
	return ed25519.PrivateKey(raw), nil
}

// EnsureSigningKeyRegistered 启动期把当前 key 自动注册到 plugin_signing_keys。
// 已存在（同 key_id）则 no-op。
//
// 调用方传公钥（从私钥派生）+ key_id；可能 nil priv 时 caller 应判断不调。
func EnsureSigningKeyRegistered(
	ctx context.Context,
	keys repo.SigningKeyRepository,
	keyID string,
	priv ed25519.PrivateKey,
	desc string,
) error {
	if priv == nil {
		return errx.New(errx.ErrPluginInvalidFormat, "私钥为 nil")
	}
	pub := priv.Public().(ed25519.PublicKey)
	k := &domain.SigningKey{
		KeyID:       keyID,
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Description: desc,
	}
	if err := keys.Insert(ctx, k); err != nil {
		var de *errx.DomainError
		if errors.As(err, &de) && de.Code == errx.ErrPluginSlugVersionExists {
			return nil // 旧 key 已注册，no-op
		}
		return err
	}
	return nil
}

// === helpers ===

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pageSizeOrDefault(s, def int) int {
	if s <= 0 {
		return def
	}
	return s
}
