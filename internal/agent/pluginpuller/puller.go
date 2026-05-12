package pluginpuller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"connectrpc.com/connect"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	plugindomain "github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// DefaultInterval 默认 30 分钟一轮。
const DefaultInterval = 30 * time.Minute

// DefaultHTTPTimeout 下载 binary 单次超时。
const DefaultHTTPTimeout = 60 * time.Second

// DefaultPlugins agent 默认拉取的 slug 列表（与 cmd/node 注册的真插件对齐）。
var DefaultPlugins = []string{"subfinder", "httpx", "nuclei", "nmap"}

// AgentClient puller 所需的 NodeAgentService 子集。
type AgentClient interface {
	ListPluginSigningKeys(
		ctx context.Context,
		req *connect.Request[tenancyv1.ListPluginSigningKeysRequest],
	) (*connect.Response[tenancyv1.ListPluginSigningKeysResponse], error)
	GetLatestPluginVersion(
		ctx context.Context,
		req *connect.Request[tenancyv1.GetLatestPluginVersionRequest],
	) (*connect.Response[tenancyv1.GetLatestPluginVersionResponse], error)
	GetPluginDownloadURL(
		ctx context.Context,
		req *connect.Request[tenancyv1.GetPluginDownloadURLRequest],
	) (*connect.Response[tenancyv1.GetPluginDownloadURLResponse], error)
}

// Logger 让 puller 可观测。匹配 internal/platform/log.Logger 子集。
type Logger interface {
	Info(msg string, args ...any)
	LogError(ctx context.Context, msg string, err error, args ...any)
}

// Config puller 启动参数。
type Config struct {
	// Slugs 要拉取的插件 slug 列表；空 → DefaultPlugins。
	Slugs []string

	// Platform 当前 agent 平台。空 → 自动按 runtime.GOOS/GOARCH 推导。
	Platform string

	// Interval 两轮拉取间隔；≤0 → DefaultInterval。
	Interval time.Duration

	// HTTPClient 下载 binary 用；nil → 默认 60s 超时 http.Client。
	HTTPClient *http.Client
}

// Puller 周期检查 + 下载 + 校验 + 安装。
type Puller struct {
	cfg      Config
	manifest *Manifest
	client   AgentClient
	http     *http.Client
	logger   Logger

	// 缓存的 signing keys：key_id → base64 公钥。启动期 + 每轮刷新。
	keysMu sync.RWMutex
	keys   map[string]string
}

// New 构造 Puller。manifest / client 必填；其它可空。
func New(manifest *Manifest, client AgentClient, cfg Config, logger Logger) (*Puller, error) {
	if manifest == nil {
		return nil, fmt.Errorf("puller: manifest 不能为 nil")
	}
	if client == nil {
		return nil, fmt.Errorf("puller: client 不能为 nil")
	}
	if len(cfg.Slugs) == 0 {
		cfg.Slugs = append([]string{}, DefaultPlugins...)
	}
	if cfg.Platform == "" {
		cfg.Platform = runtime.GOOS + "_" + runtime.GOARCH
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &Puller{
		cfg:      cfg,
		manifest: manifest,
		client:   client,
		http:     cfg.HTTPClient,
		logger:   logger,
		keys:     map[string]string{},
	}, nil
}

// Run 启动后立即执行一次 + 每 Interval 一轮，直到 ctx 取消。
func (p *Puller) Run(ctx context.Context) error {
	if err := p.refreshKeys(ctx); err != nil && p.logger != nil {
		p.logger.LogError(ctx, "pluginpuller: 启动期拉签名公钥失败", err)
	}
	if err := p.runOnce(ctx); err != nil && p.logger != nil {
		p.logger.LogError(ctx, "pluginpuller: 首轮失败", err)
	}
	ticker := time.NewTicker(p.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := p.refreshKeys(ctx); err != nil && p.logger != nil {
				p.logger.LogError(ctx, "pluginpuller: refresh keys failed", err)
			}
			if err := p.runOnce(ctx); err != nil && p.logger != nil {
				p.logger.LogError(ctx, "pluginpuller: 周期失败", err)
			}
		}
	}
}

// runOnce 单次扫所有 slug；任一 slug 失败仅 log，不阻断其它。
func (p *Puller) runOnce(ctx context.Context) error {
	for _, slug := range p.cfg.Slugs {
		if err := p.checkAndInstall(ctx, slug); err != nil {
			if p.logger != nil {
				p.logger.LogError(ctx, "pluginpuller: check slug failed", err, "slug", slug)
			}
		}
	}
	return nil
}

// checkAndInstall 比对单 slug 版本 → 必要时下载 + 安装。
func (p *Puller) checkAndInstall(ctx context.Context, slug string) error {
	// 1. 拉最新版本元数据
	resp, err := p.client.GetLatestPluginVersion(ctx, connect.NewRequest(&tenancyv1.GetLatestPluginVersionRequest{
		Slug:     slug,
		Platform: p.cfg.Platform,
	}))
	if err != nil {
		// 大部分情况是 NotFound（无可用版本）→ 静默
		return nil
	}
	pkg := resp.Msg.GetPackage()
	if pkg == nil {
		return nil
	}

	// 2. 比对 local manifest
	if cur, ok := p.manifest.Get(slug); ok {
		if cur.Version == pkg.GetVersion() && cur.SHA256 == pkg.GetSha256() {
			return nil // 已是最新
		}
	}

	if p.logger != nil {
		p.logger.Info("pluginpuller: 发现新版本，准备下载",
			"slug", slug, "version", pkg.GetVersion(), "size", pkg.GetSizeBytes())
	}

	// 3. 拿 presigned 下载 URL
	urlResp, err := p.client.GetPluginDownloadURL(ctx, connect.NewRequest(&tenancyv1.GetPluginDownloadURLRequest{
		Id: pkg.GetId(),
	}))
	if err != nil {
		return fmt.Errorf("get download url: %w", err)
	}
	downloadURL := urlResp.Msg.GetUrl()
	if downloadURL == "" {
		return fmt.Errorf("download url 为空")
	}

	// 4. 下载到 tmp
	tmpPath := p.manifest.TempPath(slug)
	gotSha, err := p.download(ctx, downloadURL, tmpPath, pkg.GetSizeBytes())
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("download: %w", err)
	}

	// 5. sha256 校验
	if gotSha != pkg.GetSha256() {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sha256 不匹配 server=%s local=%s", pkg.GetSha256(), gotSha)
	}

	// 6. ed25519 签名校验
	pubKey, ok := p.lookupKey(pkg.GetSigningKeyId())
	if !ok {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("signing_key_id %q 未在本地缓存中（可能已撤销）", pkg.GetSigningKeyId())
	}
	if err := plugindomain.VerifySignature(pubKey, gotSha, pkg.GetSignature()); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ed25519 verify: %w", err)
	}

	// 7. 原子 mv 到 plugin_dir/<slug>
	finalPath := p.manifest.BinaryPath(slug)
	if err := os.Chmod(tmpPath, 0o755); err != nil { //nolint:gosec // 可执行二进制必须有 exec 位
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	// 8. 更新 manifest
	entry := ManifestEntry{
		Slug:         slug,
		Version:      pkg.GetVersion(),
		Platform:     pkg.GetPlatform(),
		SHA256:       gotSha,
		SigningKeyID: pkg.GetSigningKeyId(),
		InstalledAt:  time.Now(),
	}
	if err := p.manifest.Put(entry); err != nil {
		return fmt.Errorf("manifest put: %w", err)
	}
	if p.logger != nil {
		p.logger.Info("pluginpuller: 安装完成",
			"slug", slug, "version", pkg.GetVersion(), "path", finalPath)
	}
	return nil
}

// download HTTP GET → 写入 path；同时算 sha256；超过 expectedSize+1MiB 防 server 异常。
func (p *Puller) download(ctx context.Context, url, path string, expectedSize int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	// 上限：expectedSize + 1MiB，防 server bug 或 GUID 替换
	maxBytes := expectedSize + 1024*1024
	if maxBytes <= 0 {
		maxBytes = 256 * 1024 * 1024
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // chmod 0755 在 install 阶段做
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)
	n, err := io.Copy(mw, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxBytes {
		return "", fmt.Errorf("响应体超过 expectedSize+1MiB (%d)", maxBytes)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// refreshKeys 拉 ListPluginSigningKeys 缓存。失败保留旧缓存。
func (p *Puller) refreshKeys(ctx context.Context) error {
	resp, err := p.client.ListPluginSigningKeys(ctx, connect.NewRequest(&tenancyv1.ListPluginSigningKeysRequest{}))
	if err != nil {
		// 若 server 端 plugin 未启用会返 Unimplemented；缓存空 map
		var cErr *connect.Error
		if errors.As(err, &cErr) && cErr.Code() == connect.CodeUnimplemented {
			return nil
		}
		return err
	}
	keys := map[string]string{}
	for _, k := range resp.Msg.GetKeys() {
		if k.RevokedAt != nil {
			continue
		}
		keys[k.GetKeyId()] = k.GetPublicKey()
	}
	p.keysMu.Lock()
	p.keys = keys
	p.keysMu.Unlock()
	return nil
}

// lookupKey 查缓存的公钥。
func (p *Puller) lookupKey(keyID string) (string, bool) {
	p.keysMu.RLock()
	defer p.keysMu.RUnlock()
	k, ok := p.keys[keyID]
	return k, ok
}

// PluginDir 暴露给 cmd/node 启动期 PATH prepend。
func (p *Puller) PluginDir() string {
	return p.manifest.Dir()
}
