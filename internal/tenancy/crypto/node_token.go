// Package crypto 是 tenancy 模块的密码学零件层（节点令牌等）。
//
// 与 identity/crypto 思路一致：高熵随机 secret + SHA-256 hex 存储；不引入慢哈希
// （token 校验是热路径，且 32 字节 crypto/rand 熵无法爆破）。
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

// 协议常量。
//
// 形态：rmnode_<43 base64url 字符>（32 字节 raw → 43 字符 base64url no-padding）
const (
	NodeTokenPrefix    = "rmnode_"
	NodeTokenSecretLen = 43 // base64.RawURLEncoding.EncodedLen(32)
	NodeTokenTotalLen  = len(NodeTokenPrefix) + NodeTokenSecretLen
)

// GeneratedNodeToken 是 GenerateNodeToken 的结果。
//
// Plaintext 仅创建时一次性返给 SA；Hash 入库；secret 不存。
type GeneratedNodeToken struct {
	Plaintext string // rmnode_<base64url(32 bytes)>
	Hash      string // SHA-256(plaintext) hex 64 字符
}

// GenerateNodeToken crypto/rand 生成新令牌。
func GenerateNodeToken() (*GeneratedNodeToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, errx.Wrap(errx.ErrCryptoEncryptionFailed, err,
			"node token: 随机生成失败")
	}
	plaintext := NodeTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return &GeneratedNodeToken{
		Plaintext: plaintext,
		Hash:      HashNodeToken(plaintext),
	}, nil
}

// HashNodeToken 算 SHA-256(plaintext) 的 hex；64 字符。
//
// 注意：hash 包含完整 plaintext（含 prefix），与 identity APIKey 仅 hash secret
// 部分不同——节点令牌没有公开 prefix 给运维识别的需求，全文 hash 更简单。
func HashNodeToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// VerifyNodeToken 常数时间对比 plaintext 与 storedHash。
func VerifyNodeToken(plaintext, storedHash string) bool {
	got := HashNodeToken(plaintext)
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1
}

// IsNodeTokenFormat 粗判 raw 是否符合节点令牌形态（长度 + 前缀）。
//
// caller 拿到 bearer 时先调此判断该走 Token 还是 JWT / API Key 流程。
func IsNodeTokenFormat(raw string) bool {
	return len(raw) == NodeTokenTotalLen && strings.HasPrefix(raw, NodeTokenPrefix)
}
