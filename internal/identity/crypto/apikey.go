package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// API Key 协议常量（LLD 10 §8.1，部分调整）。
//
// 形态：rmk_<8 prefix><40 secret>，共 52 字符。
//
// 设计偏离：LLD 写 bcrypt cost=12 存 secret，本实现改用 SHA-256：
//  1. 30 bytes crypto/rand → 240 bit 熵远超任何爆破阈值，不需慢哈希
//  2. API Key 校验在每次 RPC 都跑，慢哈希会成 DoS 放大器（攻击者塞假 key 烧 CPU）
//  3. 业内（GitHub/AWS/Stripe）API token 普遍用 SHA-256 类快哈希
const (
	APIKeyTokenPrefix = "rmk_"
	APIKeyPrefixLen   = 8  // 8 字符 base32 无歧义字母表
	APIKeySecretLen   = 40 // 40 字符 base64url（30 bytes）
	APIKeyTokenLen    = 4 + APIKeyPrefixLen + APIKeySecretLen
)

// apiKeyAlphabet 是 prefix 用的 32 字符无歧义字母表（去掉 0 / 1 / I / O）。
const apiKeyAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// GeneratedAPIKey 是 GenerateAPIKey 的结果。
//
// Plaintext 完整长令牌仅在创建时返一次给用户；Server 不留副本。
// Prefix / SecretHash 入库；Secret 不入库。
type GeneratedAPIKey struct {
	Plaintext  string // rmk_<prefix><secret>（创建后一次性返给用户）
	Prefix     string // 8 字符；UI 可见
	SecretHash string // SHA-256(secret) hex 64 字符
}

// GenerateAPIKey 用 crypto/rand 生成新 key（prefix + secret + hash）。
//
// 失败：crypto/rand 故障 → 返 ErrCryptoEncryptionFailed。
func GenerateAPIKey() (*GeneratedAPIKey, error) {
	prefix, err := randomFromAlphabet(apiKeyAlphabet, APIKeyPrefixLen)
	if err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "apikey: prefix 生成失败")
	}

	// 30 bytes → base64url 40 chars no padding
	rawSecret := make([]byte, 30)
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "apikey: secret 生成失败")
	}
	secret := base64.RawURLEncoding.EncodeToString(rawSecret)

	hash := HashAPIKeySecret(secret)
	plaintext := APIKeyTokenPrefix + prefix + secret

	return &GeneratedAPIKey{
		Plaintext:  plaintext,
		Prefix:     prefix,
		SecretHash: hash,
	}, nil
}

// HashAPIKeySecret 算 SHA-256(secret) 的 hex；64 字符。
//
// 与 ParseAPIKey 配合：解出的 secret 喂入此函数，与 DB 里的 secret_hash 比较。
func HashAPIKeySecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// VerifyAPIKeySecret 常数时间对比 secret 与 storedHash。
//
// 即便长度不等也跑一遍 ConstantTimeCompare（短路会泄露长度差异）。
func VerifyAPIKeySecret(secret, storedHash string) bool {
	got := HashAPIKeySecret(secret)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// ParseAPIKey 把 "rmk_<prefix><secret>" 拆成 (prefix, secret)。
//
// 错误：长度 / 前缀 / 字母表不合规 → ErrAuthTokenInvalid（caller 当统一错码处理）。
// 不查 secret 是否合法 base64url（只做长度校验）；hash 比对会兜。
func ParseAPIKey(raw string) (prefix, secret string, err error) {
	if len(raw) != APIKeyTokenLen {
		return "", "", errx.New(errx.ErrAuthTokenInvalid, "apikey: 长度不正确")
	}
	if !strings.HasPrefix(raw, APIKeyTokenPrefix) {
		return "", "", errx.New(errx.ErrAuthTokenInvalid, "apikey: 缺少 rmk_ 前缀")
	}
	body := raw[len(APIKeyTokenPrefix):]
	prefix = body[:APIKeyPrefixLen]
	secret = body[APIKeyPrefixLen:]

	if !isFromAlphabet(prefix, apiKeyAlphabet) {
		return "", "", errx.New(errx.ErrAuthTokenInvalid, "apikey: prefix 含非法字符")
	}
	return prefix, secret, nil
}

// randomFromAlphabet 用 crypto/rand 抽 n 个字符。
//
// 关键：用 `rand.Int` 风格的拒绝采样避免 mod 偏置。alphabet 长度必须 ≤ 256。
func randomFromAlphabet(alphabet string, n int) (string, error) {
	if alphabet == "" || len(alphabet) > 256 {
		return "", errx.New(errx.ErrInvalidInput, "alphabet 大小必须 ∈ (0, 256]")
	}
	out := make([]byte, n)
	// 256 / len(alphabet) 整除时无需拒绝采样；本场景 len=32 整除，最优。
	maxAcceptable := 256 - (256 % len(alphabet))
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= maxAcceptable {
			continue // 落入截尾区间，丢弃
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out), nil
}

// isFromAlphabet s 中每个字节都属于 alphabet。
func isFromAlphabet(s, alphabet string) bool {
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(alphabet, rune(s[i])) {
			return false
		}
	}
	return true
}
