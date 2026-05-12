// Package errx 是 RedMatrix 后端统一错误模型。
//
// 与 docs/LLD/03-error-catalog.md 严格 1:1 对齐：
//   - Code 常量按域分组（GENERAL / AUTH / AUTHZ / USER / PROJECT / ASSET / TASK /
//     NODE / PLUGIN / NOTIFY / AUDIT / REPORT / EVENT / CONFIG / CRYPTO / DIRECT /
//     BOOTSTRAP·RUNTIME）。
//   - 每个 Code 在 mapping 表中对应一个 connect.Code（详见 errx.go）。
//
// 规约（HLD §6 / 00-conventions §2.3）：
//   - 跨边界错误必须为 *DomainError（包内或 Server↔Node↔Browser）
//   - DomainError.Cause 永不暴露给客户端（仅入日志）
//   - 用户输入校验失败 → ErrValidationFailed + 多条 ValidationError details
//   - BOOTSTRAP_* 仅在启动期通过 stderr + exit code 体现，不进 RPC
package errx

// Code 是业务错误码（DOMAIN_REASON 全大写）。值与 03-error-catalog §3 严格一致。
type Code string

// String 实现 fmt.Stringer，便于日志/测试断言。
func (c Code) String() string { return string(c) }

// === 3.1 通用 GENERAL ===
const (
	ErrInternal           Code = "INTERNAL_ERROR"
	ErrDatabase           Code = "DATABASE_ERROR"
	ErrUpstreamTimeout    Code = "UPSTREAM_TIMEOUT"
	ErrInvalidInput       Code = "INVALID_INPUT"
	ErrMissingField       Code = "MISSING_FIELD"
	ErrInvalidFormat      Code = "INVALID_FORMAT"
	ErrValidationFailed   Code = "VALIDATION_FAILED"
	ErrResourceLocked     Code = "RESOURCE_LOCKED"
	ErrRateLimited        Code = "RATE_LIMITED"
	ErrNotImplemented     Code = "NOT_IMPLEMENTED"
	ErrServiceUnavailable Code = "SERVICE_UNAVAILABLE"
)

// === 3.2 认证 AUTH ===
const (
	ErrAuthFailed               Code = "AUTH_FAILED"
	ErrAuthTokenInvalid         Code = "AUTH_TOKEN_INVALID"
	ErrAuthTokenExpired         Code = "AUTH_TOKEN_EXPIRED"
	ErrAuthTokenVersionMismatch Code = "AUTH_TOKEN_VERSION_MISMATCH"
	ErrAuthAPIKeyRevoked        Code = "AUTH_API_KEY_REVOKED"
	ErrAuthCaptchaRequired      Code = "AUTH_CAPTCHA_REQUIRED"
	ErrAuthCaptchaInvalid       Code = "AUTH_CAPTCHA_INVALID"
	ErrAuthAccountLocked        Code = "AUTH_ACCOUNT_LOCKED"
	ErrAuthIPLocked             Code = "AUTH_IP_LOCKED"
	ErrAuthPasswordTooWeak      Code = "AUTH_PASSWORD_TOO_WEAK"
	ErrAuthPasswordReuse        Code = "AUTH_PASSWORD_REUSE"
	ErrAuthMustChangePassword   Code = "AUTH_MUST_CHANGE_PASSWORD"
)

// === 3.3 授权 AUTHZ ===
const (
	ErrAuthzForbidden        Code = "AUTHZ_FORBIDDEN"
	ErrAuthzRoleInsufficient Code = "AUTHZ_ROLE_INSUFFICIENT"
	ErrAuthzNotProjectMember Code = "AUTHZ_NOT_PROJECT_MEMBER"
	ErrAuthzTenantMismatch   Code = "AUTHZ_TENANT_MISMATCH"
)

// === 3.4 用户 USER ===
const (
	ErrUserNotFound                   Code = "USER_NOT_FOUND"
	ErrUserUsernameExists             Code = "USER_USERNAME_EXISTS"
	ErrUserEmailExists                Code = "USER_EMAIL_EXISTS"
	ErrUserCannotDeleteSelf           Code = "USER_CANNOT_DELETE_SELF"
	ErrUserCannotDeleteLastSuperAdmin Code = "USER_CANNOT_DELETE_LAST_SUPERADMIN"
	ErrUserRoleImmutable              Code = "USER_ROLE_IMMUTABLE"
	ErrUserUsernameImmutable          Code = "USER_USERNAME_IMMUTABLE"
	ErrUserAccountExpired             Code = "USER_ACCOUNT_EXPIRED"
	ErrSessionNotFound                Code = "SESSION_NOT_FOUND"
	ErrAPIKeyNotFound                 Code = "API_KEY_NOT_FOUND"
	ErrAccountNotFound                Code = "ACCOUNT_NOT_FOUND"
	ErrAccountSlugExists              Code = "ACCOUNT_SLUG_EXISTS"
)

// === 3.5 项目 PROJECT ===
const (
	ErrProjectNotFound          Code = "PROJECT_NOT_FOUND"
	ErrProjectMemberNotFound    Code = "PROJECT_MEMBER_NOT_FOUND"
	ErrProjectMemberExists      Code = "PROJECT_MEMBER_EXISTS"
	ErrProjectMemberRoleInvalid Code = "PROJECT_MEMBER_ROLE_INVALID"
	ErrProjectNameExists        Code = "PROJECT_NAME_EXISTS"
	ErrProjectAccessDenied      Code = "PROJECT_ACCESS_DENIED"
	ErrProjectArchived          Code = "PROJECT_ARCHIVED"
	ErrProjectHasRunningTasks   Code = "PROJECT_HAS_RUNNING_TASKS"
	ErrProjectNoAvailableNodes  Code = "PROJECT_NO_AVAILABLE_NODES"
)

// === 3.6 资产 ASSET ===
const (
	ErrAssetNotFound          Code = "ASSET_NOT_FOUND"
	ErrAssetDuplicate         Code = "ASSET_DUPLICATE"
	ErrAssetTypeInvalid       Code = "ASSET_TYPE_INVALID"
	ErrAssetNaturalKeyInvalid Code = "ASSET_NATURAL_KEY_INVALID"
	ErrAssetTypeNotManual     Code = "ASSET_TYPE_NOT_MANUAL"
	ErrAssetVersionConflict   Code = "ASSET_VERSION_CONFLICT"
)

// === 3.7 任务 TASK ===
const (
	ErrTaskNotFound         Code = "TASK_NOT_FOUND"
	ErrTaskRunNotFound      Code = "TASK_RUN_NOT_FOUND"
	ErrTaskNameExists       Code = "TASK_NAME_EXISTS"
	ErrTaskInvalidState     Code = "TASK_INVALID_STATE"
	ErrTaskNoTargets        Code = "TASK_NO_TARGETS"
	ErrTaskTemplateNotFound Code = "TASK_TEMPLATE_NOT_FOUND"
	ErrTaskCronInvalid      Code = "TASK_CRON_INVALID"
	ErrTaskProxyInvalid     Code = "TASK_PROXY_INVALID"
	ErrTaskNodeNotAvailable Code = "TASK_NODE_NOT_AVAILABLE"
	ErrTaskPluginInvalid    Code = "TASK_PLUGIN_INVALID"
)

// === 3.8 节点 NODE ===
const (
	ErrNodeNotFound                 Code = "NODE_NOT_FOUND"
	ErrNodeNameExists               Code = "NODE_NAME_EXISTS"
	ErrNodeOffline                  Code = "NODE_OFFLINE"
	ErrNodeRegistrationTokenInvalid Code = "NODE_REGISTRATION_TOKEN_INVALID"
	ErrNodeRegistrationTokenExpired Code = "NODE_REGISTRATION_TOKEN_EXPIRED"
	ErrNodeCertExpired              Code = "NODE_CERT_EXPIRED"
	ErrNodeCertRevoked              Code = "NODE_CERT_REVOKED"
	ErrNodeHasRunningTasks          Code = "NODE_HAS_RUNNING_TASKS"
	ErrNodeUpgradeFailed            Code = "NODE_UPGRADE_FAILED"
)

// === 3.9 插件 PLUGIN ===
const (
	ErrPluginNotFound                   Code = "PLUGIN_NOT_FOUND"
	ErrPluginSlugVersionExists          Code = "PLUGIN_SLUG_VERSION_EXISTS"
	ErrPluginInvalidFormat              Code = "PLUGIN_INVALID_FORMAT"
	ErrPluginTierInvalid                Code = "PLUGIN_TIER_INVALID"
	ErrPluginBinaryChecksumMismatch     Code = "PLUGIN_BINARY_CHECKSUM_MISMATCH"
	ErrPluginPrivilegeNotApproved       Code = "PLUGIN_PRIVILEGE_NOT_APPROVED"
	ErrPluginPrivilegeNotPending        Code = "PLUGIN_PRIVILEGE_NOT_PENDING"
	ErrPluginPrivilegeUnknown           Code = "PLUGIN_PRIVILEGE_UNKNOWN"
	ErrPluginPrivilegePartialNotAllowed Code = "PLUGIN_PRIVILEGE_PARTIAL_NOT_ALLOWED"
	ErrPluginPrivilegeTampered          Code = "PLUGIN_PRIVILEGE_TAMPERED"
	ErrPluginPrivilegeRejected          Code = "PLUGIN_PRIVILEGE_REJECTED"
	ErrPluginParamsInvalid              Code = "PLUGIN_PARAMS_INVALID"
	ErrPluginInstallationFailed         Code = "PLUGIN_INSTALLATION_FAILED"
	ErrPluginUpgradeBackwards           Code = "PLUGIN_UPGRADE_BACKWARDS"
	ErrPluginInUse                      Code = "PLUGIN_IN_USE"
	ErrPluginPlatformMismatch           Code = "PLUGIN_PLATFORM_MISMATCH"
	ErrPluginConfirmMismatch            Code = "PLUGIN_CONFIRM_MISMATCH"
	ErrPluginInactive                   Code = "PLUGIN_INACTIVE"
	ErrPluginNotInCache                 Code = "PLUGIN_NOT_IN_CACHE"
	ErrPluginDownload                   Code = "PLUGIN_DOWNLOAD"
	ErrPluginHandshakeFailed            Code = "PLUGIN_HANDSHAKE_FAILED"
	ErrPluginUnavailable                Code = "PLUGIN_UNAVAILABLE"
	ErrPluginCapabilityViolation        Code = "PLUGIN_CAPABILITY_VIOLATION"
	ErrPluginActivate                   Code = "PLUGIN_ACTIVATE"
)

// === 3.10 通知 NOTIFY ===
const (
	ErrChannelNotFound    Code = "CHANNEL_NOT_FOUND"
	ErrChannelURLInvalid  Code = "CHANNEL_URL_INVALID"
	ErrChannelTypeInvalid Code = "CHANNEL_TYPE_INVALID"
	ErrChannelTestFailed  Code = "CHANNEL_TEST_FAILED"
	ErrDeliveryNotFound   Code = "DELIVERY_NOT_FOUND"
)

// === 3.11 审计 AUDIT ===
const (
	ErrAuditLogNotFound          Code = "AUDIT_LOG_NOT_FOUND"
	ErrAuditChainBroken          Code = "AUDIT_CHAIN_BROKEN"
	ErrAuditVerificationRunning  Code = "AUDIT_VERIFICATION_RUNNING"
	ErrAuditVerificationNotFound Code = "AUDIT_VERIFICATION_NOT_FOUND"
)

// === 3.12 报告 REPORT ===
const (
	ErrReportNotFound         Code = "REPORT_NOT_FOUND"
	ErrReportGenerationFailed Code = "REPORT_GENERATION_FAILED"
	ErrReportExpired          Code = "REPORT_EXPIRED"
	ErrReportTooLarge         Code = "REPORT_TOO_LARGE"
)

// === 3.13 漏洞工作流 FINDING（PR-S26）===
const (
	ErrFindingNotFound          Code = "FINDING_NOT_FOUND"
	ErrFindingInvalidTransition Code = "FINDING_INVALID_TRANSITION"
)

// === 3.13 事件 EVENT ===
const (
	ErrEventNotFound Code = "EVENT_NOT_FOUND"
)

// === 3.14 配置 CONFIG ===
const (
	ErrConfigLockedByEnv      Code = "CONFIG_LOCKED_BY_ENV"
	ErrConfigValidationFailed Code = "CONFIG_VALIDATION_FAILED"
)

// === 3.15 加密 / 密钥 CRYPTO ===
const (
	ErrCryptoEncryptionFailed   Code = "CRYPTO_ENCRYPTION_FAILED"
	ErrCryptoDecryptionFailed   Code = "CRYPTO_DECRYPTION_FAILED"
	ErrCryptoKeyRotationRunning Code = "CRYPTO_KEY_ROTATION_RUNNING"
	ErrCryptoKeyNotFound        Code = "CRYPTO_KEY_NOT_FOUND"
)

// === 3.16 模块间调用 DIRECT ===
const (
	ErrInternalCallForbidden Code = "INTERNAL_CALL_FORBIDDEN"
)

// === 3.17 启动校验 / 运行时 BOOTSTRAP / RUNTIME ===
const (
	ErrBootstrapCryptoInvalid     Code = "BOOTSTRAP_CRYPTO_INVALID"
	ErrBootstrapKeyReuseForbidden Code = "BOOTSTRAP_KEY_REUSE_FORBIDDEN"
	ErrBootstrapConfigInvalid     Code = "BOOTSTRAP_CONFIG_INVALID"
	ErrBootstrapDBUnreachable     Code = "BOOTSTRAP_DB_UNREACHABLE"
	ErrBootstrapPKIInvalid        Code = "BOOTSTRAP_PKI_INVALID"
	ErrBootstrapStorageMissing    Code = "BOOTSTRAP_STORAGE_MISSING"
	ErrBootstrapGuardViolation    Code = "BOOTSTRAP_GUARD_VIOLATION"
	ErrRuntimeSandboxUnavailable  Code = "RUNTIME_SANDBOX_UNAVAILABLE"
	ErrMetricsUnavailable         Code = "METRICS_UNAVAILABLE"
)

// AllCodes 列出所有已定义错误码，便于测试覆盖性校验。
// 维护规则：新增 const Code 必须同时追加到此 slice。
var AllCodes = []Code{
	// GENERAL
	ErrInternal, ErrDatabase, ErrUpstreamTimeout, ErrInvalidInput, ErrMissingField,
	ErrInvalidFormat, ErrValidationFailed, ErrResourceLocked, ErrRateLimited,
	ErrNotImplemented, ErrServiceUnavailable,
	// AUTH
	ErrAuthFailed, ErrAuthTokenInvalid, ErrAuthTokenExpired, ErrAuthTokenVersionMismatch,
	ErrAuthAPIKeyRevoked, ErrAuthCaptchaRequired, ErrAuthCaptchaInvalid,
	ErrAuthAccountLocked, ErrAuthIPLocked, ErrAuthPasswordTooWeak, ErrAuthPasswordReuse,
	ErrAuthMustChangePassword,
	// AUTHZ
	ErrAuthzForbidden, ErrAuthzRoleInsufficient, ErrAuthzNotProjectMember, ErrAuthzTenantMismatch,
	// USER
	ErrUserNotFound, ErrUserUsernameExists, ErrUserEmailExists, ErrUserCannotDeleteSelf,
	ErrUserCannotDeleteLastSuperAdmin, ErrUserRoleImmutable, ErrUserUsernameImmutable,
	ErrUserAccountExpired, ErrSessionNotFound, ErrAPIKeyNotFound,
	ErrAccountNotFound, ErrAccountSlugExists,
	// PROJECT
	ErrProjectNotFound, ErrProjectNameExists, ErrProjectAccessDenied, ErrProjectArchived,
	ErrProjectHasRunningTasks, ErrProjectNoAvailableNodes,
	ErrProjectMemberNotFound, ErrProjectMemberExists, ErrProjectMemberRoleInvalid,
	// ASSET
	ErrAssetNotFound, ErrAssetDuplicate, ErrAssetTypeInvalid, ErrAssetNaturalKeyInvalid,
	ErrAssetTypeNotManual, ErrAssetVersionConflict,
	// TASK
	ErrTaskNotFound, ErrTaskRunNotFound, ErrTaskNameExists, ErrTaskInvalidState,
	ErrTaskNoTargets, ErrTaskTemplateNotFound, ErrTaskCronInvalid, ErrTaskProxyInvalid,
	ErrTaskNodeNotAvailable, ErrTaskPluginInvalid,
	// NODE
	ErrNodeNotFound, ErrNodeNameExists, ErrNodeOffline, ErrNodeRegistrationTokenInvalid,
	ErrNodeRegistrationTokenExpired, ErrNodeCertExpired, ErrNodeCertRevoked,
	ErrNodeHasRunningTasks, ErrNodeUpgradeFailed,
	// PLUGIN
	ErrPluginNotFound, ErrPluginSlugVersionExists, ErrPluginInvalidFormat,
	ErrPluginTierInvalid, ErrPluginBinaryChecksumMismatch, ErrPluginPrivilegeNotApproved,
	ErrPluginPrivilegeNotPending, ErrPluginPrivilegeUnknown, ErrPluginPrivilegePartialNotAllowed,
	ErrPluginPrivilegeTampered, ErrPluginPrivilegeRejected, ErrPluginParamsInvalid,
	ErrPluginInstallationFailed, ErrPluginUpgradeBackwards, ErrPluginInUse,
	ErrPluginPlatformMismatch, ErrPluginConfirmMismatch, ErrPluginInactive,
	ErrPluginNotInCache, ErrPluginDownload, ErrPluginHandshakeFailed, ErrPluginUnavailable,
	ErrPluginCapabilityViolation, ErrPluginActivate,
	// NOTIFY
	ErrChannelNotFound, ErrChannelURLInvalid, ErrChannelTypeInvalid, ErrChannelTestFailed,
	ErrDeliveryNotFound,
	// AUDIT
	ErrAuditLogNotFound, ErrAuditChainBroken, ErrAuditVerificationRunning,
	ErrAuditVerificationNotFound,
	// REPORT
	ErrReportNotFound, ErrReportGenerationFailed, ErrReportExpired, ErrReportTooLarge,
	// FINDING（PR-S26）
	ErrFindingNotFound, ErrFindingInvalidTransition,
	// EVENT
	ErrEventNotFound,
	// CONFIG
	ErrConfigLockedByEnv, ErrConfigValidationFailed,
	// CRYPTO
	ErrCryptoEncryptionFailed, ErrCryptoDecryptionFailed, ErrCryptoKeyRotationRunning,
	ErrCryptoKeyNotFound,
	// DIRECT
	ErrInternalCallForbidden,
	// BOOTSTRAP / RUNTIME
	ErrBootstrapCryptoInvalid, ErrBootstrapKeyReuseForbidden, ErrBootstrapConfigInvalid,
	ErrBootstrapDBUnreachable, ErrBootstrapPKIInvalid, ErrBootstrapStorageMissing,
	ErrBootstrapGuardViolation, ErrRuntimeSandboxUnavailable, ErrMetricsUnavailable,
}
