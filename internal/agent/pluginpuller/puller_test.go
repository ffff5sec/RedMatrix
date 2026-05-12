package pluginpuller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	plugindomain "github.com/ffff5sec/RedMatrix/internal/pluginpkg/domain"
)

// === manifest 测试 ===

func TestManifest_LoadEmpty(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(m.Entries) != 0 {
		t.Errorf("空 dir 应有 0 entries, got %d", len(m.Entries))
	}
}

func TestManifest_PutAndLoad(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)
	entry := ManifestEntry{
		Slug: "subfinder", Version: "2.6.3", Platform: "linux_amd64",
		SHA256: "abc", SigningKeyID: "k1", InstalledAt: time.Now(),
	}
	if err := m.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 重新 Load 验证持久化
	m2, _ := LoadManifest(dir)
	got, ok := m2.Get("subfinder")
	if !ok {
		t.Fatal("subfinder 应存在")
	}
	if got.Version != "2.6.3" {
		t.Errorf("got version %q, want 2.6.3", got.Version)
	}
}

// === Puller 集成测试 ===

type stubAgentClient struct {
	keys     []*tenancyv1.PluginSigningKey
	pkg      *tenancyv1.PluginPackageRef
	dlURL    string
	keyErr   error
	pkgErr   error
	dlErr    error
	keyCalls int
	pkgCalls int
	dlCalls  int
}

func (s *stubAgentClient) ListPluginSigningKeys(_ context.Context, _ *connect.Request[tenancyv1.ListPluginSigningKeysRequest]) (*connect.Response[tenancyv1.ListPluginSigningKeysResponse], error) {
	s.keyCalls++
	if s.keyErr != nil {
		return nil, s.keyErr
	}
	return connect.NewResponse(&tenancyv1.ListPluginSigningKeysResponse{Keys: s.keys}), nil
}
func (s *stubAgentClient) GetLatestPluginVersion(_ context.Context, _ *connect.Request[tenancyv1.GetLatestPluginVersionRequest]) (*connect.Response[tenancyv1.GetLatestPluginVersionResponse], error) {
	s.pkgCalls++
	if s.pkgErr != nil {
		return nil, s.pkgErr
	}
	return connect.NewResponse(&tenancyv1.GetLatestPluginVersionResponse{Package: s.pkg}), nil
}
func (s *stubAgentClient) GetPluginDownloadURL(_ context.Context, _ *connect.Request[tenancyv1.GetPluginDownloadURLRequest]) (*connect.Response[tenancyv1.GetPluginDownloadURLResponse], error) {
	s.dlCalls++
	if s.dlErr != nil {
		return nil, s.dlErr
	}
	return connect.NewResponse(&tenancyv1.GetPluginDownloadURLResponse{
		Url:       s.dlURL,
		ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
	}), nil
}

func setupPullerWithBinary(t *testing.T, binary []byte) (*Puller, *stubAgentClient, string) {
	t.Helper()
	dir := t.TempDir()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 生成 ed25519 keypair + 签 binary 的 sha256
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sha := plugindomain.ComputeSHA256Hex(binary)
	sig := plugindomain.SignSHA256(priv, sha)

	// HTTP server 返 binary
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(binary)
	}))
	t.Cleanup(srv.Close)

	stub := &stubAgentClient{
		keys: []*tenancyv1.PluginSigningKey{
			{KeyId: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)},
		},
		pkg: &tenancyv1.PluginPackageRef{
			Id:           "pkg-1",
			Slug:         "subfinder",
			Version:      "2.6.3",
			Platform:     "linux_amd64",
			Sha256:       sha,
			Signature:    sig,
			SigningKeyId: "k1",
			//nolint:gosec // test 数据
			SizeBytes: int64(len(binary)),
		},
		dlURL: srv.URL,
	}

	puller, err := New(m, stub, Config{
		Slugs:    []string{"subfinder"},
		Platform: "linux_amd64",
		Interval: time.Hour,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return puller, stub, dir
}

func TestPuller_HappyPath_InstallsBinary(t *testing.T) {
	binary := []byte("fake binary content")
	puller, _, dir := setupPullerWithBinary(t, binary)
	if err := puller.refreshKeys(context.Background()); err != nil {
		t.Fatalf("refreshKeys: %v", err)
	}
	if err := puller.checkAndInstall(context.Background(), "subfinder"); err != nil {
		t.Fatalf("checkAndInstall: %v", err)
	}
	binPath := filepath.Join(dir, "subfinder")
	got, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatalf("read installed: %v", err)
	}
	if string(got) != string(binary) {
		t.Errorf("binary mismatch")
	}
	// 检查 exec 位
	info, _ := os.Stat(binPath)
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("缺 exec 位: %v", info.Mode())
	}
	// manifest 更新
	entry, ok := puller.manifest.Get("subfinder")
	if !ok {
		t.Fatal("manifest 应有 subfinder")
	}
	if entry.Version != "2.6.3" {
		t.Errorf("manifest version = %q", entry.Version)
	}
}

func TestPuller_TamperedBinary_Refused(t *testing.T) {
	dir := t.TempDir()
	m, _ := LoadManifest(dir)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	originalBin := []byte("good binary")
	sha := plugindomain.ComputeSHA256Hex(originalBin)
	sig := plugindomain.SignSHA256(priv, sha)

	// HTTP server 返被篡改的 binary
	tamperedBin := []byte("MALICIOUS")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tamperedBin)
	}))
	defer srv.Close()

	stub := &stubAgentClient{
		keys: []*tenancyv1.PluginSigningKey{
			{KeyId: "k1", PublicKey: base64.StdEncoding.EncodeToString(pub)},
		},
		pkg: &tenancyv1.PluginPackageRef{
			Id: "pkg-1", Slug: "subfinder", Version: "2.6.3", Platform: "linux_amd64",
			Sha256: sha, Signature: sig, SigningKeyId: "k1", SizeBytes: int64(len(originalBin)),
		},
		dlURL: srv.URL,
	}

	puller, _ := New(m, stub, Config{
		Slugs: []string{"subfinder"}, Platform: "linux_amd64",
	}, nil)
	_ = puller.refreshKeys(context.Background())
	err := puller.checkAndInstall(context.Background(), "subfinder")
	if err == nil {
		t.Fatal("篡改应失败")
	}
	// 篡改 sha 校验失败前缀
	if got := err.Error(); !contains(got, "sha256 不匹配") {
		t.Errorf("want sha mismatch, got %v", err)
	}
	// 不应安装
	if _, err := os.Stat(filepath.Join(dir, "subfinder")); err == nil {
		t.Error("篡改后不应有 binary")
	}
}

func TestPuller_UnknownKey_Refused(t *testing.T) {
	binary := []byte("ok")
	puller, stub, dir := setupPullerWithBinary(t, binary)
	// 强行把 pkg 的 signing_key_id 改成不存在的
	stub.pkg.SigningKeyId = "unknown-key"
	_ = puller.refreshKeys(context.Background())
	err := puller.checkAndInstall(context.Background(), "subfinder")
	if err == nil {
		t.Fatal("未知 key 应失败")
	}
	if _, err := os.Stat(filepath.Join(dir, "subfinder")); err == nil {
		t.Error("应未安装")
	}
}

func TestPuller_SameVersion_NoOp(t *testing.T) {
	binary := []byte("v1")
	puller, _, _ := setupPullerWithBinary(t, binary)
	_ = puller.refreshKeys(context.Background())
	// 预填 manifest 表示已是最新
	sha := plugindomain.ComputeSHA256Hex(binary)
	_ = puller.manifest.Put(ManifestEntry{
		Slug: "subfinder", Version: "2.6.3", SHA256: sha,
	})
	if err := puller.checkAndInstall(context.Background(), "subfinder"); err != nil {
		t.Fatalf("no-op should succeed: %v", err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || stringContains(s, sub))
}
func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
