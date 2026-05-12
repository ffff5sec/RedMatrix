package domain

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestCompareVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"v1.0.0", "1.0.0", 0},
		{"2.0.0", "1.9.9", 1},
		{"1.10.0", "1.2.0", 1}, // 10 > 2 数字比较
		{"1.0", "1.0.0", 0},
	}
	for _, c := range cases {
		got := CompareVersion(c.a, c.b)
		if got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestIsNewerVersion(t *testing.T) {
	if !IsNewerVersion("1.0.0", "1.0.1") {
		t.Error("1.0.1 应比 1.0.0 新")
	}
	if IsNewerVersion("1.0.0", "1.0.0") {
		t.Error("同版本不应是新")
	}
	if IsNewerVersion("2.0.0", "1.9.9") {
		t.Error("1.9.9 不应比 2.0.0 新")
	}
}

func TestComputeSHA256Hex(t *testing.T) {
	h := ComputeSHA256Hex([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if h != want {
		t.Errorf("want %q, got %q", want, h)
	}
	if !ValidSHA256Hex(h) {
		t.Error("ComputeSHA256Hex 输出应通过 ValidSHA256Hex")
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	sha := ComputeSHA256Hex([]byte("plugin-binary-blob"))
	sig := SignSHA256(priv, sha)

	if err := VerifySignature(pubB64, sha, sig); err != nil {
		t.Errorf("verify 应通过: %v", err)
	}

	// 篡改 sha：换个不同的 sha
	otherSha := ComputeSHA256Hex([]byte("different-blob"))
	if err := VerifySignature(pubB64, otherSha, sig); err == nil {
		t.Error("篡改 sha 应失败")
	}
	// 篡改签名
	if err := VerifySignature(pubB64, sha, "abc"+sig[3:]); err == nil {
		t.Error("篡改签名应失败")
	}
}

func TestValidateForCreate_Package(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	sha := ComputeSHA256Hex([]byte("binary"))
	sig := SignSHA256(priv, sha)

	ok := &PluginPackage{
		Slug: "subfinder", Version: "2.6.3", Platform: PlatformLinuxAMD64,
		ArtifactKey: "plugins/subfinder/2.6.3/linux_amd64/bin", SHA256: sha,
		Signature: sig, SigningKeyID: "k1", SizeBytes: 1234,
	}
	if err := ok.ValidateForCreate(); err != nil {
		t.Errorf("ok 应通过: %v", err)
	}

	bad := []*PluginPackage{
		{Slug: "", Version: "2", Platform: PlatformLinuxAMD64, ArtifactKey: "k", SHA256: sha, Signature: sig, SigningKeyID: "k1", SizeBytes: 1},
		{Slug: "x", Version: "", Platform: PlatformLinuxAMD64, ArtifactKey: "k", SHA256: sha, Signature: sig, SigningKeyID: "k1", SizeBytes: 1},
		{Slug: "x", Version: "1", Platform: "bogus", ArtifactKey: "k", SHA256: sha, Signature: sig, SigningKeyID: "k1", SizeBytes: 1},
		{Slug: "x", Version: "1", Platform: PlatformLinuxAMD64, ArtifactKey: "k", SHA256: "not-hex", Signature: sig, SigningKeyID: "k1", SizeBytes: 1},
		{Slug: "x", Version: "1", Platform: PlatformLinuxAMD64, ArtifactKey: "k", SHA256: sha, Signature: "", SigningKeyID: "k1", SizeBytes: 1},
		{Slug: "x", Version: "1", Platform: PlatformLinuxAMD64, ArtifactKey: "k", SHA256: sha, Signature: sig, SigningKeyID: "k1", SizeBytes: 0},
	}
	for i, p := range bad {
		if err := p.ValidateForCreate(); err == nil {
			t.Errorf("bad[%d] 应失败", i)
		}
	}
}

func TestValidateForCreate_SigningKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ok := &SigningKey{
		KeyID:     "redmatrix-2026",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	if err := ok.ValidateForCreate(); err != nil {
		t.Errorf("ok 应通过: %v", err)
	}
	bad := []*SigningKey{
		{KeyID: "", PublicKey: base64.StdEncoding.EncodeToString(pub)},
		{KeyID: "k", PublicKey: "not-base64-!@#"},
		{KeyID: "k", PublicKey: base64.StdEncoding.EncodeToString([]byte("short"))}, // 长度错
	}
	for i, k := range bad {
		if err := k.ValidateForCreate(); err == nil {
			t.Errorf("bad[%d] 应失败", i)
		}
	}
}
