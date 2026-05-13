// pluginpkg/service_test.go PR-S45 —— 插件包 service 单测。
//
// 覆盖：
//   - UploadPackage: 缺签名 key 拒；空 binary / 超限 / 非法 platform 拒；
//     happy path 写 MinIO + repo；repo Insert 失败回滚 MinIO object
//   - GetLatestVersion: SemVer 排序（v10 > v9 而非字典序）；deprecated 跳过；
//     无可用版本返 ErrPluginNotFound
//   - GetDownloadURL: deprecated 拒；is_active=false 拒；happy path
//   - List/Get/SetActive/Deprecate: 透传 repo
//   - SigningKey: List/Register/Revoke 透传
package pluginpkg

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net/url"
	"testing"
	"time"

	miniogo "github.com/minio/minio-go/v7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
	"github.com/ffff5sec/RedMatrix/internal/pluginpkg/repo"
)

// === stubs ===

type stubPkgRepo struct {
	byID      map[string]*domain.PluginPackage
	rows      []*domain.PluginPackage // 按 Insert 顺序
	insertErr error
}

func newStubPkgRepo() *stubPkgRepo { return &stubPkgRepo{byID: map[string]*domain.PluginPackage{}} }

func (r *stubPkgRepo) Insert(_ context.Context, p *domain.PluginPackage) error {
	if r.insertErr != nil {
		return r.insertErr
	}
	if p.ID == "" {
		p.ID = "pkg-" + p.Slug + "-" + p.Version + "-" + string(p.Platform)
	}
	p.UploadedAt = time.Now()
	r.rows = append(r.rows, p)
	r.byID[p.ID] = p
	return nil
}
func (r *stubPkgRepo) GetByID(_ context.Context, id string) (*domain.PluginPackage, error) {
	p, ok := r.byID[id]
	if !ok {
		return nil, errx.New(errx.ErrPluginNotFound, "not found")
	}
	return p, nil
}
func (r *stubPkgRepo) List(_ context.Context, filter repo.PluginFilter, _ repo.Page) ([]*domain.PluginPackage, int, error) {
	out := []*domain.PluginPackage{}
	for _, p := range r.rows {
		if filter.Slug != "" && p.Slug != filter.Slug {
			continue
		}
		if filter.Platform != "" && string(p.Platform) != filter.Platform {
			continue
		}
		if filter.Active != nil && p.IsActive != *filter.Active {
			continue
		}
		out = append(out, p)
	}
	return out, len(out), nil
}
func (r *stubPkgRepo) GetLatestActive(_ context.Context, _ string, _ string) (*domain.PluginPackage, error) {
	return nil, errx.New(errx.ErrPluginNotFound, "stub: unused in PR-S38 后实现")
}
func (r *stubPkgRepo) UpdateActive(_ context.Context, id string, isActive bool) error {
	p, ok := r.byID[id]
	if !ok {
		return errx.New(errx.ErrPluginNotFound, "not found")
	}
	p.IsActive = isActive
	return nil
}
func (r *stubPkgRepo) Deprecate(_ context.Context, id string) error {
	p, ok := r.byID[id]
	if !ok {
		return errx.New(errx.ErrPluginNotFound, "not found")
	}
	now := time.Now()
	p.DeprecatedAt = &now
	return nil
}

type stubKeyRepo struct {
	keys      []*domain.SigningKey
	insertErr error
}

func (r *stubKeyRepo) Insert(_ context.Context, k *domain.SigningKey) error {
	if r.insertErr != nil {
		return r.insertErr
	}
	if k.ID == "" {
		k.ID = "key-" + k.KeyID
	}
	r.keys = append(r.keys, k)
	return nil
}
func (r *stubKeyRepo) GetByKeyID(_ context.Context, keyID string) (*domain.SigningKey, error) {
	for _, k := range r.keys {
		if k.KeyID == keyID {
			return k, nil
		}
	}
	return nil, errx.New(errx.ErrPluginNotFound, "not found")
}
func (r *stubKeyRepo) ListActive(_ context.Context) ([]*domain.SigningKey, error) {
	out := []*domain.SigningKey{}
	for _, k := range r.keys {
		if k.RevokedAt == nil {
			out = append(out, k)
		}
	}
	return out, nil
}
func (r *stubKeyRepo) Revoke(_ context.Context, keyID string) error {
	for _, k := range r.keys {
		if k.KeyID == keyID {
			now := time.Now()
			k.RevokedAt = &now
			return nil
		}
	}
	return errx.New(errx.ErrPluginNotFound, "not found")
}

// stubMinIO 简化：内存模拟 PutObject/RemoveObject/Presign。
type stubMinIO struct {
	objects    map[string][]byte // key → content
	putErr     error
	removeErr  error
	presignErr error
	removeLog  []string // 记录 RemoveObject 被调到的 key
}

func newStubMinIO() *stubMinIO { return &stubMinIO{objects: map[string][]byte{}} }

func (m *stubMinIO) PutObject(_ context.Context, _, key string, r io.Reader, _ int64, _ miniogo.PutObjectOptions) (miniogo.UploadInfo, error) {
	if m.putErr != nil {
		return miniogo.UploadInfo{}, m.putErr
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return miniogo.UploadInfo{}, err
	}
	m.objects[key] = b
	return miniogo.UploadInfo{Key: key, Size: int64(len(b))}, nil
}
func (m *stubMinIO) PresignedGetObject(_ context.Context, _, key string, _ time.Duration, _ url.Values) (*url.URL, error) {
	if m.presignErr != nil {
		return nil, m.presignErr
	}
	return url.Parse("https://example.test/" + key + "?sig=xxx")
}
func (m *stubMinIO) RemoveObject(_ context.Context, _, key string, _ miniogo.RemoveObjectOptions) error {
	m.removeLog = append(m.removeLog, key)
	if m.removeErr != nil {
		return m.removeErr
	}
	delete(m.objects, key)
	return nil
}

// === harness ===

type harness struct {
	svc   Service
	pkgs  *stubPkgRepo
	keys  *stubKeyRepo
	minio *stubMinIO
	priv  ed25519.PrivateKey
	keyID string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_ = pub
	keyID := "test-key-2026"
	pkgs := newStubPkgRepo()
	keys := &stubKeyRepo{}
	minio := newStubMinIO()
	svc, err := New(Deps{
		Packages: pkgs, SigningKeys: keys, MinIO: minio,
		SigningKeyID: keyID, SigningPrivate: priv,
	})
	require.NoError(t, err)
	return &harness{svc: svc, pkgs: pkgs, keys: keys, minio: minio, priv: priv, keyID: keyID}
}

// === Upload ===

func TestUploadPackage_HappyPath(t *testing.T) {
	h := newHarness(t)
	pkg, err := h.svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "nuclei", Version: "v1.0.0", Platform: "linux_amd64",
		Binary: []byte("fake binary content"), UploaderID: "u-1",
	})
	require.NoError(t, err)
	require.NotNil(t, pkg)
	assert.Equal(t, "nuclei", pkg.Slug)
	assert.Equal(t, h.keyID, pkg.SigningKeyID)
	assert.NotEmpty(t, pkg.SHA256)
	assert.NotEmpty(t, pkg.Signature)
	assert.True(t, pkg.IsActive)
	// MinIO 写了 1 个 object，且与 ArtifactKey 一致
	assert.Len(t, h.minio.objects, 1)
	_, ok := h.minio.objects[pkg.ArtifactKey]
	assert.True(t, ok)
	// repo 落了 1 条
	assert.Len(t, h.pkgs.rows, 1)
}

func TestUploadPackage_NoSigningKey_Rejected(t *testing.T) {
	pkgs := newStubPkgRepo()
	keys := &stubKeyRepo{}
	svc, err := New(Deps{Packages: pkgs, SigningKeys: keys, MinIO: newStubMinIO()}) // 无 SigningPrivate
	require.NoError(t, err)
	_, err = svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "nuclei", Version: "v1", Platform: "linux_amd64", Binary: []byte("x"),
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginInstallationFailed, code)
}

func TestUploadPackage_EmptyBinary_Rejected(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64",
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginInvalidFormat, code)
}

func TestUploadPackage_OverSize_Rejected(t *testing.T) {
	h := newHarness(t)
	huge := make([]byte, MaxUploadSize+1)
	_, err := h.svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: huge,
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginInvalidFormat, code)
}

func TestUploadPackage_InvalidPlatform_Rejected(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "x", Version: "v1", Platform: "freebsd_amd64", Binary: []byte("x"),
	})
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginPlatformMismatch, code)
}

// TestUploadPackage_InsertFails_RollsBackMinIO PR-S45：repo Insert 失败必须
// 调 MinIO.RemoveObject 清理已上传 object，避免泄露孤儿 binary。
func TestUploadPackage_InsertFails_RollsBackMinIO(t *testing.T) {
	h := newHarness(t)
	h.pkgs.insertErr = errx.New(errx.ErrPluginSlugVersionExists, "重复")
	_, err := h.svc.UploadPackage(context.Background(), UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: []byte("data"),
	})
	require.Error(t, err)
	assert.Len(t, h.minio.removeLog, 1, "Insert 失败应触发 MinIO RemoveObject 回滚")
	assert.Empty(t, h.minio.objects, "object 已被清理")
}

// === GetLatestVersion ===

// TestGetLatestVersion_SemVerOrder PR-S38 修过：v10 > v9 而非字典序。
// 这里 regression 测：同 slug+platform 下 v0.9.0 / v0.10.0 / v0.11.0，
// 返 v0.11.0（最高 SemVer）。
func TestGetLatestVersion_SemVerOrder(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, v := range []string{"v0.9.0", "v0.10.0", "v0.11.0"} {
		_, err := h.svc.UploadPackage(ctx, UploadRequest{
			Slug: "tool", Version: v, Platform: "linux_amd64", Binary: []byte(v),
		})
		require.NoError(t, err)
	}
	best, err := h.svc.GetLatestVersion(ctx, "tool", "linux_amd64")
	require.NoError(t, err)
	assert.Equal(t, "v0.11.0", best.Version, "SemVer 排序 v0.11 > v0.10 > v0.9")
}

func TestGetLatestVersion_SkipDeprecated(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for _, v := range []string{"v1.0.0", "v2.0.0", "v3.0.0"} {
		_, err := h.svc.UploadPackage(ctx, UploadRequest{
			Slug: "tool", Version: v, Platform: "linux_amd64", Binary: []byte(v),
		})
		require.NoError(t, err)
	}
	// 把最新版本 deprecate
	latest := h.pkgs.rows[2]
	require.NoError(t, h.svc.DeprecatePackage(ctx, latest.ID))

	best, err := h.svc.GetLatestVersion(ctx, "tool", "linux_amd64")
	require.NoError(t, err)
	assert.Equal(t, "v2.0.0", best.Version, "应跳过 deprecated 取次新")
}

func TestGetLatestVersion_NoAvailable_ReturnsErrPluginNotFound(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.GetLatestVersion(context.Background(), "missing", "linux_amd64")
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginNotFound, code)
}

func TestGetLatestVersion_InvalidPlatform_Rejected(t *testing.T) {
	h := newHarness(t)
	_, err := h.svc.GetLatestVersion(context.Background(), "x", "android_arm64")
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginPlatformMismatch, code)
}

// === GetDownloadURL ===

func TestGetDownloadURL_HappyPath(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pkg, err := h.svc.UploadPackage(ctx, UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: []byte("a"),
	})
	require.NoError(t, err)
	u, expires, err := h.svc.GetDownloadURL(ctx, pkg.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, u)
	assert.True(t, expires.After(time.Now()))
}

func TestGetDownloadURL_Deprecated_Rejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pkg, err := h.svc.UploadPackage(ctx, UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: []byte("a"),
	})
	require.NoError(t, err)
	require.NoError(t, h.svc.DeprecatePackage(ctx, pkg.ID))

	_, _, err = h.svc.GetDownloadURL(ctx, pkg.ID)
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginInactive, code)
}

func TestGetDownloadURL_Inactive_Rejected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	pkg, err := h.svc.UploadPackage(ctx, UploadRequest{
		Slug: "x", Version: "v1", Platform: "linux_amd64", Binary: []byte("a"),
	})
	require.NoError(t, err)
	require.NoError(t, h.svc.SetActive(ctx, pkg.ID, false))

	_, _, err = h.svc.GetDownloadURL(ctx, pkg.ID)
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrPluginInactive, code)
}

// === SigningKey CRUD 透传 ===

func TestSigningKey_RegisterListRevoke(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	k := &domain.SigningKey{KeyID: "k1", PublicKey: "pub1", Description: "test"}
	out, err := h.svc.RegisterSigningKey(ctx, k)
	require.NoError(t, err)
	assert.Equal(t, "k1", out.KeyID)

	keys, err := h.svc.ListSigningKeys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	require.NoError(t, h.svc.RevokeSigningKey(ctx, "k1"))
	keys, err = h.svc.ListSigningKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, keys, "revoked key 不应列在 active 中")
}
