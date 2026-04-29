package domain

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// argon2id 推荐参数（OWASP 2023 / RFC 9106 平衡安全与性能）。
//
// 生产可视具体硬件按 LLD 04 §3.1 security.password.* 调；改参数后哈希值 PHC
// 字符串内会带新参数，旧 hash 仍可正确 verify（参数从字串解析）。
const (
	argonTimeCost   = uint32(1)
	argonMemoryCost = uint32(64 * 1024) // 64 MiB
	argonThreads    = uint8(4)
	argonKeyLen     = uint32(32)
	argonSaltLen    = 16
)

// HashPassword 用 argon2id 哈希明文密码，返回标准 PHC 字串。
//
//	$argon2id$v=19$m=65536,t=1,p=4$<salt-base64>$<hash-base64>
//
// salt 由 crypto/rand 生成（每次哈希都不同 — 同明文每次返回不同结果）。
func HashPassword(plain string) (string, error) {
	if plain == "" {
		return "", errx.New(errx.ErrInvalidInput, "password 不能为空")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", errx.Wrap(errx.ErrCryptoEncryptionFailed, err, "argon2: read salt")
	}
	hash := argon2.IDKey([]byte(plain), salt, argonTimeCost, argonMemoryCost, argonThreads, argonKeyLen)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemoryCost, argonTimeCost, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
	return encoded, nil
}

// VerifyPassword 用 PHC 字串验证明文。time-constant 比较防侧信道。
//
// 返回:
//   - (true, nil)  匹配
//   - (false, nil) 不匹配（合法 hash 字串）
//   - (false, err) hash 字串本身格式错（应被视为内部 bug，非用户密码错）
func VerifyPassword(plain, encoded string) (bool, error) {
	if plain == "" || encoded == "" {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	// "" / "argon2id" / "v=N" / "m=...,t=...,p=..." / "<salt>" / "<hash>"
	if len(parts) != 6 {
		return false, errors.New("argon2: invalid hash format (expect 6 segments)")
	}
	if parts[1] != "argon2id" {
		return false, fmt.Errorf("argon2: unsupported variant %q", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("argon2: invalid version segment: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("argon2: unsupported version %d (need %d)", version, argon2.Version)
	}

	var memory, timeCost uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &threads); err != nil {
		return false, fmt.Errorf("argon2: invalid params segment: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("argon2: invalid salt b64: %w", err)
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("argon2: invalid hash b64: %w", err)
	}
	// 防御 PHC 解码出来的 hash 长度异常（合法 argon2 输出常 32 字节；框 16-1024 拦垃圾）。
	if len(expected) < 16 || len(expected) > 1024 {
		return false, fmt.Errorf("argon2: hash length %d out of range [16,1024]", len(expected))
	}
	keyLen := uint32(len(expected)) //nolint:gosec // 上面已限制 ≤1024，远小于 uint32 上限

	computed := argon2.IDKey([]byte(plain), salt, timeCost, memory, threads, keyLen)
	return subtle.ConstantTimeCompare(expected, computed) == 1, nil
}
