// Package domain 插件包分发模块的领域类型（PR-S28）。
//
// 范围：
//   - PluginPackage：上传到服务器的插件二进制包（slug + version + platform 唯一）
//   - SigningKey：ed25519 公钥（私钥不入 DB，server 走 env）
//   - 版本比较 + 签名验证 helper
package domain

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Platform agent 运行平台（与 GOOS_GOARCH 对齐）。
type Platform string

const (
	PlatformLinuxAMD64   Platform = "linux_amd64"
	PlatformLinuxARM64   Platform = "linux_arm64"
	PlatformDarwinAMD64  Platform = "darwin_amd64"
	PlatformDarwinARM64  Platform = "darwin_arm64"
	PlatformWindowsAMD64 Platform = "windows_amd64"
)

// Valid 判定 platform 合法。
func (p Platform) Valid() bool {
	switch p {
	case PlatformLinuxAMD64, PlatformLinuxARM64,
		PlatformDarwinAMD64, PlatformDarwinARM64,
		PlatformWindowsAMD64:
		return true
	}
	return false
}

// SlugMaxLen schema VARCHAR(64) 对齐。
const SlugMaxLen = 64

// VersionMaxLen schema VARCHAR(32) 对齐。
const VersionMaxLen = 32

// ArtifactKeyMaxLen schema VARCHAR(256) 对齐。
const ArtifactKeyMaxLen = 256

// SigningKeyIDMaxLen schema VARCHAR(64) 对齐。
const SigningKeyIDMaxLen = 64

// PluginPackage 单个版本的插件二进制包。
type PluginPackage struct {
	ID           string
	Slug         string
	Version      string
	Platform     Platform
	ArtifactKey  string
	SHA256       string // hex 64 字符
	Signature    string // base64 ed25519
	SigningKeyID string
	SizeBytes    int64
	Description  string
	IsActive     bool
	UploadedBy   string
	UploadedAt   time.Time
	DeprecatedAt *time.Time
}

// ValidateForCreate INSERT 前的全部域内规则。
func (p *PluginPackage) ValidateForCreate() error {
	if p == nil {
		return errx.New(errx.ErrInvalidInput, "plugin_package is nil")
	}
	if strings.TrimSpace(p.Slug) == "" {
		return errx.New(errx.ErrInvalidInput, "plugin.slug 不能为空")
	}
	if len(p.Slug) > SlugMaxLen {
		return errx.New(errx.ErrInvalidInput, "plugin.slug 超出长度").
			WithFields("max", SlugMaxLen)
	}
	if strings.TrimSpace(p.Version) == "" {
		return errx.New(errx.ErrInvalidInput, "plugin.version 不能为空")
	}
	if len(p.Version) > VersionMaxLen {
		return errx.New(errx.ErrInvalidInput, "plugin.version 超出长度").
			WithFields("max", VersionMaxLen)
	}
	if !p.Platform.Valid() {
		return errx.New(errx.ErrPluginPlatformMismatch, "plugin.platform 不合法").
			WithFields("got", string(p.Platform))
	}
	if strings.TrimSpace(p.ArtifactKey) == "" {
		return errx.New(errx.ErrInvalidInput, "plugin.artifact_key 不能为空")
	}
	if !ValidSHA256Hex(p.SHA256) {
		return errx.New(errx.ErrPluginBinaryChecksumMismatch,
			"plugin.sha256 不是合法的 64 字符 hex")
	}
	if strings.TrimSpace(p.Signature) == "" {
		return errx.New(errx.ErrInvalidInput, "plugin.signature 不能为空")
	}
	if strings.TrimSpace(p.SigningKeyID) == "" {
		return errx.New(errx.ErrInvalidInput, "plugin.signing_key_id 不能为空")
	}
	if p.SizeBytes <= 0 {
		return errx.New(errx.ErrPluginInvalidFormat, "plugin.size 必须 > 0")
	}
	return nil
}

// IsDeprecated 软停用。
func (p *PluginPackage) IsDeprecated() bool {
	return p != nil && p.DeprecatedAt != nil
}

// SigningKey ed25519 公钥（私钥不入 DB）。
type SigningKey struct {
	ID          string
	KeyID       string // 用户友好短 ID，例如 'redmatrix-2026'
	PublicKey   string // base64 ed25519 32 字节
	Description string
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

// IsRevoked true → agent 不再信任此 key 签的包。
func (k *SigningKey) IsRevoked() bool {
	return k != nil && k.RevokedAt != nil
}

// ValidateForCreate INSERT 前校验。
func (k *SigningKey) ValidateForCreate() error {
	if k == nil {
		return errx.New(errx.ErrInvalidInput, "signing_key is nil")
	}
	if strings.TrimSpace(k.KeyID) == "" {
		return errx.New(errx.ErrInvalidInput, "key_id 不能为空")
	}
	if len(k.KeyID) > SigningKeyIDMaxLen {
		return errx.New(errx.ErrInvalidInput, "key_id 超出长度").
			WithFields("max", SigningKeyIDMaxLen)
	}
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil {
		return errx.New(errx.ErrInvalidInput, "public_key 不是合法的 base64").
			WithFields("err", err.Error())
	}
	if len(pub) != ed25519.PublicKeySize {
		return errx.New(errx.ErrInvalidInput, "public_key 长度错").
			WithFields("got", len(pub), "want", ed25519.PublicKeySize)
	}
	return nil
}

// === 加密辅助 ===

// ValidSHA256Hex 校 64 字符全 hex。
func ValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// ComputeSHA256Hex 给定 bytes 算 sha256 → hex。
func ComputeSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SignSHA256 用 ed25519 私钥对 sha256 hex 字符串签名；返 base64 sig。
//
// 签名对象是 sha256 hex string（非原始 bytes），便于审计可读。
// 调用方保证 priv 长度 = ed25519.PrivateKeySize。
func SignSHA256(priv ed25519.PrivateKey, sha256Hex string) string {
	sig := ed25519.Sign(priv, []byte(sha256Hex))
	return base64.StdEncoding.EncodeToString(sig)
}

// VerifySignature 用 base64 公钥验证 sha256Hex 的签名。
func VerifySignature(publicKeyB64, sha256Hex, sigB64 string) error {
	pub, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return errx.New(errx.ErrInvalidInput, "public_key 解码失败")
	}
	if len(pub) != ed25519.PublicKeySize {
		return errx.New(errx.ErrInvalidInput, "public_key 长度错")
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return errx.New(errx.ErrInvalidInput, "signature 解码失败")
	}
	if !ed25519.Verify(pub, []byte(sha256Hex), sig) {
		return errx.New(errx.ErrPluginBinaryChecksumMismatch, "ed25519 签名校验失败")
	}
	return nil
}

// === 版本比较（SemVer-lite）===

// IsNewerVersion 判定 b 是否比 a 新；不支持完整 SemVer，仅按 dot-splited int 串比。
// 非数字段按字符串比；'v' 前缀剥掉。
// 用例：a="2.6.3", b="2.6.4" → true；a="v2.6.3", b="2.6.3" → false（视作等）。
func IsNewerVersion(a, b string) bool {
	return compareVersion(b, a) > 0
}

// CompareVersion a<b → -1；a==b → 0；a>b → 1。
func CompareVersion(a, b string) int {
	return compareVersion(a, b)
}

func compareVersion(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		ai, aOK := parseIntStrict(av)
		bi, bOK := parseIntStrict(bv)
		if aOK && bOK {
			if ai != bi {
				if ai < bi {
					return -1
				}
				return 1
			}
			continue
		}
		// 字符串比
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}

func parseIntStrict(s string) (int, bool) {
	if s == "" {
		return 0, true
	}
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		n = n*10 + int(ch-'0')
	}
	return n, true
}
