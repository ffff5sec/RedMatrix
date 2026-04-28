package bootstrapcheck

import (
	"github.com/ffff5sec/RedMatrix/internal/config"
)

// CheckConfig 把 config.Config 中"运维容易写错"的字段送进 Default Guard 扫一遍。
// 字段挑选原则：
//   - 凭据类（密码 / token）：必检
//   - URL / DSN 整体：跳过（url 含 "admin@host" 会误中 WeakDefault）
//   - 长二进制密钥（base64 ENCRYPTION_KEY 等）：跳过 PlaceholderToken（长度足够熵高）
//   - Bootstrap.Username / Email：跳过（"admin" 是 LLD 04 §2.2 约定默认值；
//     email 任意域名不入危险集）
//
// 命中 high → BOOTSTRAP_GUARD_VIOLATION，否则 nil。
func CheckConfig(cfg *config.Config) error {
	if cfg == nil {
		return nil
	}
	g := Default()
	items := map[string]string{
		// 字符串密钥可能被误填占位 / 弱值
		"config.Crypto.JWTSecret":   cfg.Crypto.JWTSecret,
		"config.Bootstrap.Password": cfg.Bootstrap.Password,
		"config.DB.MinIOAccessKey":  cfg.DB.MinIOAccessKey,
		"config.DB.MinIOSecretKey":  cfg.DB.MinIOSecretKey,
		"config.Public.Domain":      cfg.Public.Domain,
	}
	return g.CheckMap(items)
}
