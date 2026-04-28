package config

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// 密钥长度（D40-06 + 04 §2.1）。
const (
	minJWTSecretLen = 64
	keyByteLen      = 32
)

// 角色名（22-rls §4.4）。
const (
	roleApp         = "redmatrix_app"
	roleMaintenance = "redmatrix_maintenance"
)

// Validate 跑 04 §3.4 + 40 §2.5 / §9.6 的全部静态校验。
//   - 不做网络连接（PG ping / ES health 等由 cmd/server 启动序列处理）
//   - 多个错误会按发现顺序聚合 / 返回首个；调用方收到后立即 exit 2
//
// 返回的 error 永远是 *errx.DomainError，Code ∈ BOOTSTRAP_*。
func (c *Config) Validate() error {
	if c == nil {
		return errx.New(errx.ErrBootstrapConfigInvalid, "Config is nil")
	}

	checks := []func(*Config) error{
		validateRequiredEnv,
		validateCrypto,
		validateKeyUniqueness,
		validatePGDSN,
		validateLog,
	}
	for _, fn := range checks {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}

// validateRequiredEnv 检查所有 04 §2.1 / §2.3 标记 "必填" 的 env 是否齐全。
func validateRequiredEnv(c *Config) error {
	type req struct {
		field string
		value string
	}
	required := []req{
		{"PG_DSN", c.DB.PGDSN},
		{"PG_DSN_MAINTENANCE", c.DB.PGMaintenanceDSN},
		{"ES_URL", c.DB.ESURL},
		{"REDIS_URL", c.DB.RedisURL},
		{"MINIO_ENDPOINT", c.DB.MinIOEndpoint},
		{"MINIO_PUBLIC_ENDPOINT", c.DB.MinIOPublicEndpoint},
		{"MINIO_ACCESS_KEY", c.DB.MinIOAccessKey},
		{"MINIO_SECRET_KEY", c.DB.MinIOSecretKey},
		{"PUBLIC_DOMAIN", c.Public.Domain},
		{"PUBLIC_GRPC_ADDR", c.Public.GRPCAddr},
		{"PUBLIC_MINIO_ADDR", c.Public.MinIOAddr},
		{"JWT_SECRET", c.Crypto.JWTSecret},
	}
	for _, r := range required {
		if r.value == "" {
			return errx.New(errx.ErrBootstrapConfigInvalid,
				fmt.Sprintf("必填环境变量缺失: %s", r.field)).
				WithFields("var", r.field)
		}
	}
	return nil
}

// validateCrypto 校验 4 个密钥的强度与编码。
func validateCrypto(c *Config) error {
	if len(c.Crypto.JWTSecret) < minJWTSecretLen {
		return errx.New(errx.ErrBootstrapCryptoInvalid,
			"JWT_SECRET 长度必须 ≥ 64 字符").
			WithFields("var", "JWT_SECRET", "got_len", len(c.Crypto.JWTSecret))
	}
	for _, k := range []struct {
		name string
		val  []byte
	}{
		{"ENCRYPTION_KEY", c.Crypto.EncryptionKey},
		{"AUDIT_HMAC_KEY", c.Crypto.AuditHMACKey},
		{"BACKUP_KEY", c.Crypto.BackupKey},
	} {
		if len(k.val) == 0 {
			return errx.New(errx.ErrBootstrapCryptoInvalid,
				"密钥未配置").WithFields("var", k.name)
		}
		if len(k.val) != keyByteLen {
			return errx.New(errx.ErrBootstrapCryptoInvalid,
				"密钥长度必须为 32 字节（base64 解码后）").
				WithFields("var", k.name, "got_bytes", len(k.val))
		}
	}
	return nil
}

// validateKeyUniqueness 强制 ENCRYPTION_KEY ≠ AUDIT_HMAC_KEY ≠ BACKUP_KEY（D40-06）。
func validateKeyUniqueness(c *Config) error {
	pairs := []struct{ a, b, aname, bname string }{
		{string(c.Crypto.EncryptionKey), string(c.Crypto.AuditHMACKey),
			"ENCRYPTION_KEY", "AUDIT_HMAC_KEY"},
		{string(c.Crypto.EncryptionKey), string(c.Crypto.BackupKey),
			"ENCRYPTION_KEY", "BACKUP_KEY"},
		{string(c.Crypto.AuditHMACKey), string(c.Crypto.BackupKey),
			"AUDIT_HMAC_KEY", "BACKUP_KEY"},
	}
	for _, p := range pairs {
		if bytes.Equal([]byte(p.a), []byte(p.b)) {
			return errx.New(errx.ErrBootstrapKeyReuseForbidden,
				"两个密钥不可相同（防主密钥泄漏导致备份同时失守，40 D40-06）").
				WithFields("var_a", p.aname, "var_b", p.bname)
		}
	}
	return nil
}

// validatePGDSN 校验 PG_DSN 与 PG_DSN_MAINTENANCE：
//   - sslmode 不可为 disable
//   - PG_DSN 用户应为 redmatrix_app（22-rls §4.4）
//   - PG_DSN_MAINTENANCE 用户必须是 redmatrix_maintenance
func validatePGDSN(c *Config) error {
	if err := requireSSLEnabled(c.DB.PGDSN, "PG_DSN"); err != nil {
		return err
	}
	if err := requireSSLEnabled(c.DB.PGMaintenanceDSN, "PG_DSN_MAINTENANCE"); err != nil {
		return err
	}
	if err := requireUser(c.DB.PGMaintenanceDSN, "PG_DSN_MAINTENANCE", roleMaintenance); err != nil {
		return err
	}
	// PG_DSN 的 role 不强校验为 redmatrix_app —— 部分本地开发会用 postgres 超管。
	// PG_DSN_ADMIN 也不强校验（仅 CI / 升级注入，可能格式不同）。
	if c.DB.PGAdminDSN != "" {
		if err := requireSSLEnabled(c.DB.PGAdminDSN, "PG_DSN_ADMIN"); err != nil {
			return err
		}
	}
	return nil
}

func requireSSLEnabled(dsn, name string) error {
	if dsn == "" {
		return nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return errx.Wrap(errx.ErrBootstrapConfigInvalid, err,
			fmt.Sprintf("%s 解析失败", name)).WithFields("var", name)
	}
	if !strings.HasPrefix(u.Scheme, "postgres") {
		return errx.New(errx.ErrBootstrapConfigInvalid,
			fmt.Sprintf("%s scheme 必须为 postgres / postgresql（实为 %s）", name, u.Scheme)).
			WithFields("var", name, "got_scheme", u.Scheme)
	}
	mode := u.Query().Get("sslmode")
	if mode == "disable" {
		return errx.New(errx.ErrBootstrapConfigInvalid,
			fmt.Sprintf("%s sslmode=disable 不允许（生产必须 require / verify-full）", name)).
			WithFields("var", name)
	}
	return nil
}

func requireUser(dsn, name, expected string) error {
	if dsn == "" {
		return nil
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return errx.Wrap(errx.ErrBootstrapConfigInvalid, err,
			fmt.Sprintf("%s 解析失败", name)).WithFields("var", name)
	}
	if u.User == nil || u.User.Username() != expected {
		got := ""
		if u.User != nil {
			got = u.User.Username()
		}
		return errx.New(errx.ErrBootstrapConfigInvalid,
			fmt.Sprintf("%s 用户名不符（要 %s，实为 %s；22-rls §4.4 要求严格分工）",
				name, expected, got)).
			WithFields("var", name, "expected", expected, "got", got)
	}
	return nil
}

// validateLog 校验 log.level / log.format 取值在合法集。
func validateLog(c *Config) error {
	if !contains(c.Log.Level, "trace", "debug", "info", "warn", "error") {
		return errx.New(errx.ErrBootstrapConfigInvalid,
			"LOG_LEVEL 取值非法").
			WithFields("got", c.Log.Level)
	}
	if !contains(c.Log.Format, "json", "text") {
		return errx.New(errx.ErrBootstrapConfigInvalid,
			"LOG_FORMAT 取值非法").
			WithFields("got", c.Log.Format)
	}
	return nil
}

func contains(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}
