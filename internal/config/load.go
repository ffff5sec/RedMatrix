package config

import (
	"encoding/base64"
	"os"
	"strconv"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// EnvSource 是 env 来源抽象（默认 os.Getenv，测试时可注入 map）。
type EnvSource func(key string) string

// LoadOptions 是 Load 的可选参数。
type LoadOptions struct {
	env EnvSource
}

// Option 函数式选项。
type Option func(*LoadOptions)

// WithEnvSource 注入 env 来源（测试用；默认走 os.Getenv）。
func WithEnvSource(env map[string]string) Option {
	return func(o *LoadOptions) {
		o.env = func(k string) string {
			return env[k]
		}
	}
}

// Load 从 env 读取并构造 *Config。
//   - 不读取 YAML / DB（后续 PR 接入）
//   - 不做连通性检查（启动期 cmd/server 单独处理）
//   - base64 字段（ENCRYPTION_KEY 等）解析失败立即返回 BOOTSTRAP_CRYPTO_INVALID
//   - 如需 fail-fast 校验请额外调用 (*Config).Validate()
func Load(opts ...Option) (*Config, error) {
	o := &LoadOptions{env: os.Getenv}
	for _, opt := range opts {
		opt(o)
	}
	get := o.env

	// === Crypto（base64 字段需立即解码）===
	encKey, err := decodeKey(get("ENCRYPTION_KEY"))
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapCryptoInvalid, err,
			"ENCRYPTION_KEY 不是合法 base64 32 字节").
			WithFields("var", "ENCRYPTION_KEY")
	}
	hmacKey, err := decodeKey(get("AUDIT_HMAC_KEY"))
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapCryptoInvalid, err,
			"AUDIT_HMAC_KEY 不是合法 base64 32 字节").
			WithFields("var", "AUDIT_HMAC_KEY")
	}
	backupKey, err := decodeKey(get("BACKUP_KEY"))
	if err != nil {
		return nil, errx.Wrap(errx.ErrBootstrapCryptoInvalid, err,
			"BACKUP_KEY 不是合法 base64 32 字节").
			WithFields("var", "BACKUP_KEY")
	}

	cfg := &Config{
		Env:     stringOrDefault(get("ENV"), "prod"),
		Version: get("VERSION"),

		Public: PublicConfig{
			Domain:        get("PUBLIC_DOMAIN"),
			GRPCAddr:      get("PUBLIC_GRPC_ADDR"),
			IngestAddr:    deriveIngest(get("PUBLIC_INGEST_ADDR"), get("PUBLIC_GRPC_ADDR")),
			MinIOAddr:     get("PUBLIC_MINIO_ADDR"),
			GrafanaURL:    get("PUBLIC_GRAFANA_URL"),
			PrometheusURL: get("PUBLIC_PROMETHEUS_URL"),
		},

		DB: DBConfig{
			PGDSN:               get("PG_DSN"),
			PGMaintenanceDSN:    get("PG_DSN_MAINTENANCE"),
			PGAdminDSN:          get("PG_DSN_ADMIN"),
			ESURL:               get("ES_URL"),
			RedisURL:            get("REDIS_URL"),
			MinIOEndpoint:       get("MINIO_ENDPOINT"),
			MinIOPublicEndpoint: get("MINIO_PUBLIC_ENDPOINT"),
			MinIOAccessKey:      get("MINIO_ACCESS_KEY"),
			MinIOSecretKey:      get("MINIO_SECRET_KEY"),
		},

		Crypto: CryptoConfig{
			JWTSecret:     get("JWT_SECRET"),
			EncryptionKey: encKey,
			AuditHMACKey:  hmacKey,
			BackupKey:     backupKey,
		},

		Bootstrap: BootstrapAdmin{
			Username: stringOrDefault(get("ADMIN_BOOTSTRAP_USERNAME"), "admin"),
			Password: get("ADMIN_BOOTSTRAP_PASSWORD"),
			// 默认必须含 TLD —— users.email 域校验要求 local@domain.tld 形态。
			Email: stringOrDefault(get("ADMIN_BOOTSTRAP_EMAIL"), "admin@example.com"),
		},

		Log: LogConfig{
			Level:  stringOrDefault(get("LOG_LEVEL"), "info"),
			Format: stringOrDefault(get("LOG_FORMAT"), "json"),
		},

		Dev: DevFlags{
			AutoMigrate: parseBool(get("RM_AUTO_MIGRATE"), true),
			DevMode:     parseBool(get("RM_DEV_MODE"), false),
			LEStaging:   parseBool(get("LE_STAGING"), false),
		},
	}

	return cfg, nil
}

// decodeKey 解析 base64 编码的 32 字节密钥。空字符串返回 nil（后续由 Validate 检测必填性）。
func decodeKey(s string) ([]byte, error) {
	if s == "" {
		return nil, nil //nolint:nilnil // 空允许，由 Validate 报缺失
	}
	// 同时接受标准 + URL-safe + 带 / 不带 padding（运维生成时容易混）
	for _, dec := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := dec.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, &decodeError{input: s}
}

type decodeError struct{ input string }

func (e *decodeError) Error() string {
	return "base64 decode failed (input length " + strconv.Itoa(len(e.input)) + ")"
}

// deriveIngest 推导 IngestService 端点：显式 env 优先；否则把 GRPCAddr 端口换 9091。
// 详见 13-scan D-43：控制面 :9090 / 数据面 :9091。
func deriveIngest(explicit, grpcAddr string) string {
	if explicit != "" {
		return explicit
	}
	if grpcAddr == "" {
		return ""
	}
	host, _, ok := splitHostPort(grpcAddr)
	if !ok {
		return ""
	}
	return host + ":9091"
}

// splitHostPort 把 "host:port" 拆分；不依赖 net 包以保持纯静态行为。
func splitHostPort(s string) (host, port string, ok bool) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

func stringOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// parseBool 解析常见 truthy 字符串；失败时返回 def（不上报错误，避免无谓阻断启动）。
func parseBool(s string, def bool) bool {
	if s == "" {
		return def
	}
	v, err := strconv.ParseBool(s)
	if err != nil {
		return def
	}
	return v
}
