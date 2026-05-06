// Package config 是 RedMatrix 启动期配置加载与校验。
//
// 与 docs/LLD/04-config-schema.md / docs/LLD/40-deployment-detail.md §2.5 + §9.6 对齐：
//   - 启动期仅读 env（YAML / DB system_settings 在后续 PR 接入）
//   - Validate 实施 §9.6 的 fail-fast 静态检查（密钥长度 / base64 / 三密钥互异 /
//     PG sslmode / maintenance role 名）
//   - 连通性检查（PG ping / ES health 等）由 cmd/server 启动序列单独处理，不在本包
//
// 失败模式：返回 *errx.DomainError，Code ∈ BOOTSTRAP_* 系列；
// 调用方应据此 fmt.Fprintln(os.Stderr, err); os.Exit(2)。
package config

// Config 启动期完整配置（env 部分）。
//
// 注意：当前仅含 bootstrap 必需字段；YAML / DB 层各业务模块字段将在后续 PR
// 按需扩充（见 04-config-schema.md §3.1 完整结构）。
type Config struct {
	// Env 部署环境标记（"prod" | "staging" | "dev"，default "prod"）。
	Env string

	// Version 容器镜像 tag / 二进制版本（同 internal/version.Version；可选 env VERSION）。
	Version string

	// Public 对外暴露的域名 / 端口（节点接入 + UI 跳转）。
	Public PublicConfig

	// DB 数据存储连接串与凭据。
	DB DBConfig

	// Crypto 4 个加密 / 签名 / 备份密钥。Validate 后保证非空且互异。
	Crypto CryptoConfig

	// Bootstrap 首次启动的管理员账号占位。
	Bootstrap BootstrapAdmin

	// Log 日志输出策略（env override：LOG_LEVEL / LOG_FORMAT）。
	Log LogConfig

	// Dev 开发模式开关 / Caddy ACME staging 等。
	Dev DevFlags
}

// PublicConfig 对外暴露端点。详见 04 §2.3 + 40 §1.4。
type PublicConfig struct {
	// Domain 例 "redmatrix.example.com"。Caddy ACME / Web SPA 主域。
	Domain string

	// GRPCAddr NodeService（控制面）端点；例 "grpc.example.com:9090"（13-scan D-43）。
	GRPCAddr string

	// IngestAddr IngestService（数据面）端点；例 "grpc.example.com:9091"（同上）。
	IngestAddr string

	// MinIOAddr 节点拉插件 / UI 预签名下载域（公网）；例 "minio.example.com:9000"。
	MinIOAddr string

	// GrafanaURL 监控页 iframe 跳转（可选）。
	GrafanaURL string

	// PrometheusURL 仅运维内网链接（可选）。
	PrometheusURL string
}

// DBConfig 数据存储连接串。22-rls §4.4 强制双连接（app + maintenance）。
type DBConfig struct {
	// PGDSN 应用连接（redmatrix_app role，受 RLS 约束）。必填。
	PGDSN string

	// PGMaintenanceDSN 维护连接（redmatrix_maintenance role，旁路 RLS）。必填。
	PGMaintenanceDSN string

	// PGAdminDSN 管理员（redmatrix_admin role，goose 迁移用）。可选；
	// 仅 CI / 升级时注入，应用容器不持有。
	PGAdminDSN string

	// ESURL Elasticsearch 端点；多节点逗号分隔。必填。
	ESURL string

	// RedisURL `redis://[:pass@]host:port/db` 形式。必填。
	RedisURL string

	// MinIOEndpoint 内网 endpoint（docker network 内）；例 "minio:9000"。必填。
	MinIOEndpoint string

	// MinIOPublicEndpoint 公网 endpoint（节点拉插件用）；例 "minio.example.com:9000"。必填。
	MinIOPublicEndpoint string

	// MinIOAccessKey / MinIOSecretKey MinIO root 凭据。必填。
	MinIOAccessKey string
	MinIOSecretKey string
}

// CryptoConfig 4 个不可同时存在于一处的密钥（D40-06）。
//
//   - JWTSecret：原始字符串，长度 ≥ 64
//   - EncryptionKey / AuditHMACKey / BackupKey：base64-decoded 后必须正好 32 字节
type CryptoConfig struct {
	// JWTSecret 原始 ASCII（长度 ≥ 64）。env JWT_SECRET。
	JWTSecret string

	// EncryptionKey 32 字节主加密密钥（base64 输入，本字段为解码后字节）。
	EncryptionKey []byte

	// AuditHMACKey 32 字节审计链 HMAC 密钥。
	AuditHMACKey []byte

	// BackupKey 32 字节备份独立密钥。必须与上两者互异（40 D40-06）。
	BackupKey []byte
}

// BootstrapAdmin 首次启动 SuperAdmin 占位（详见 04 §2.2）。
type BootstrapAdmin struct {
	// Username 默认 "admin"。env ADMIN_BOOTSTRAP_USERNAME。
	Username string

	// Password 留空 = 启动期生成强随机并 stdout 输出一次（仅首启）。
	Password string

	// Email 默认 "admin@example.com"。env ADMIN_BOOTSTRAP_EMAIL。
	// 默认含 TLD：users.email 域校验要求 local@domain.tld 形态。
	Email string
}

// LogConfig 日志输出（与 HLD §5 / 04 §3.1 log: 段对齐）。
type LogConfig struct {
	// Level trace | debug | info | warn | error，默认 "info"。
	Level string

	// Format json | text，默认 "json"。
	Format string
}

// DevFlags 开发 / 部署相关开关。
type DevFlags struct {
	// AutoMigrate 启动时自动跑 PG 迁移（仅开发档默认 true，详见 40 D40-07）。
	// env RM_AUTO_MIGRATE。
	AutoMigrate bool

	// DevMode 开发模式（详见 04 §2.5）。生产应为 false。
	// env RM_DEV_MODE。
	DevMode bool

	// LEStaging Caddy 使用 Let's Encrypt staging（开发环境必开）。
	// env LE_STAGING。
	LEStaging bool
}
