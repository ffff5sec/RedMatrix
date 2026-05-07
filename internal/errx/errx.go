package errx

import (
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
)

// DomainError 是业务层 / 跨边界错误的标准容器。
// 必须通过 New / Wrap / Wrapf 构造（不要直接 struct literal）。
type DomainError struct {
	// Code 业务码（详见 codes.go）。
	Code Code

	// Message 用户可读消息（中文，i18n 在 Phase 2 启用）。
	Message string

	// Cause 底层错误。永远不会通过 Connect 暴露，仅入日志。
	Cause error

	// Fields 上下文字段（结构化日志 / 排错使用）。
	// 通过 Connect 暴露时序列化为 map[string]string（详见 connect.go）。
	Fields map[string]any

	// connectCode 是从 Code 派生出的 connect.Code，构造时计算并冻结。
	connectCode connect.Code
}

// === 构造器 ===

// New 构造一个 DomainError（无底层错误）。
func New(code Code, message string) *DomainError {
	return &DomainError{
		Code:        code,
		Message:     message,
		connectCode: connectCodeFor(code),
	}
}

// Wrap 包装底层错误，message 用于用户可读消息（不会泄漏 cause）。
func Wrap(code Code, cause error, message string) *DomainError {
	return &DomainError{
		Code:        code,
		Message:     message,
		Cause:       cause,
		connectCode: connectCodeFor(code),
	}
}

// Wrapf 同 Wrap，但 message 走 fmt.Sprintf。
func Wrapf(code Code, cause error, format string, args ...any) *DomainError {
	return Wrap(code, cause, fmt.Sprintf(format, args...))
}

// Internal 是 Wrap 的语义糖：表示 Connect Internal 类错误且总是带 cause。
// 与 HLD §6 / 00-conventions §2.3 示例对齐：
//
//	return errx.Internal(errx.ErrDatabase, err).WithFields("op", "asset.get", ...)
func Internal(code Code, cause error) *DomainError {
	return Wrap(code, cause, "")
}

// === 链式增强 ===

// WithFields 链式追加上下文字段。kv 必须成对（key 必须是 string）。
// 奇数长度时自动补齐，避免 panic。
func (e *DomainError) WithFields(kv ...any) *DomainError {
	if e == nil {
		return nil
	}
	if len(kv)%2 != 0 {
		kv = append(kv, "<MISSING>")
	}
	if e.Fields == nil {
		e.Fields = make(map[string]any, len(kv)/2)
	}
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok || k == "" {
			continue
		}
		e.Fields[k] = kv[i+1]
	}
	return e
}

// WithMessage 覆盖 user-facing message（不影响 Cause）。
func (e *DomainError) WithMessage(msg string) *DomainError {
	if e == nil {
		return nil
	}
	e.Message = msg
	return e
}

// === 标准 error 接口 ===

// Error 实现 error。包含 Cause 用于日志可见性，但 ToConnect 不会序列化 Cause。
func (e *DomainError) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString(string(e.Code))
	if e.Message != "" {
		b.WriteString(": ")
		b.WriteString(e.Message)
	}
	if e.Cause != nil {
		b.WriteString(" (cause: ")
		b.WriteString(e.Cause.Error())
		b.WriteString(")")
	}
	return b.String()
}

// Unwrap 让 errors.Is / errors.As 能穿透到 Cause。
func (e *DomainError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// ConnectCode 返回派生的 connect.Code（构造时冻结）。
func (e *DomainError) ConnectCode() connect.Code {
	if e == nil {
		return connect.CodeUnknown
	}
	return e.connectCode
}

// === 辅助函数 ===

// IsCode 判断 err 链中是否含指定 Code 的 DomainError。
func IsCode(err error, code Code) bool {
	var de *DomainError
	if !errors.As(err, &de) {
		return false
	}
	return de.Code == code
}

// GetCode 提取 err 链上首个 DomainError 的 Code。
func GetCode(err error) (Code, bool) {
	var de *DomainError
	if !errors.As(err, &de) {
		return "", false
	}
	return de.Code, true
}

// === Code → connect.Code 映射（与 03-error-catalog §3 / §4 严格 1:1） ===

var codeToConnect = map[Code]connect.Code{
	// GENERAL
	ErrInternal:           connect.CodeInternal,
	ErrDatabase:           connect.CodeInternal,
	ErrUpstreamTimeout:    connect.CodeDeadlineExceeded,
	ErrInvalidInput:       connect.CodeInvalidArgument,
	ErrMissingField:       connect.CodeInvalidArgument,
	ErrInvalidFormat:      connect.CodeInvalidArgument,
	ErrValidationFailed:   connect.CodeInvalidArgument,
	ErrResourceLocked:     connect.CodeFailedPrecondition,
	ErrRateLimited:        connect.CodeResourceExhausted,
	ErrNotImplemented:     connect.CodeUnimplemented,
	ErrServiceUnavailable: connect.CodeUnavailable,

	// AUTH
	ErrAuthFailed:               connect.CodeUnauthenticated,
	ErrAuthTokenInvalid:         connect.CodeUnauthenticated,
	ErrAuthTokenExpired:         connect.CodeUnauthenticated,
	ErrAuthTokenVersionMismatch: connect.CodeUnauthenticated,
	ErrAuthAPIKeyRevoked:        connect.CodeUnauthenticated,
	ErrAuthCaptchaRequired:      connect.CodeInvalidArgument,
	ErrAuthCaptchaInvalid:       connect.CodeInvalidArgument,
	ErrAuthAccountLocked:        connect.CodePermissionDenied,
	ErrAuthIPLocked:             connect.CodeResourceExhausted,
	ErrAuthPasswordTooWeak:      connect.CodeInvalidArgument,
	ErrAuthPasswordReuse:        connect.CodeInvalidArgument,
	ErrAuthMustChangePassword:   connect.CodeFailedPrecondition,

	// AUTHZ
	ErrAuthzForbidden:        connect.CodePermissionDenied,
	ErrAuthzRoleInsufficient: connect.CodePermissionDenied,
	ErrAuthzNotProjectMember: connect.CodePermissionDenied,
	ErrAuthzTenantMismatch:   connect.CodePermissionDenied,

	// USER
	ErrUserNotFound:                   connect.CodeNotFound,
	ErrUserUsernameExists:             connect.CodeAlreadyExists,
	ErrUserEmailExists:                connect.CodeAlreadyExists,
	ErrUserCannotDeleteSelf:           connect.CodeInvalidArgument,
	ErrUserCannotDeleteLastSuperAdmin: connect.CodeInvalidArgument,
	ErrUserRoleImmutable:              connect.CodeInvalidArgument,
	ErrUserUsernameImmutable:          connect.CodeInvalidArgument,
	ErrUserAccountExpired:             connect.CodeUnauthenticated,
	ErrSessionNotFound:                connect.CodeNotFound,
	ErrAPIKeyNotFound:                 connect.CodeNotFound,
	ErrAccountNotFound:                connect.CodeNotFound,
	ErrAccountSlugExists:              connect.CodeAlreadyExists,

	// PROJECT
	ErrProjectNotFound:          connect.CodeNotFound,
	ErrProjectMemberNotFound:    connect.CodeNotFound,
	ErrProjectMemberExists:      connect.CodeAlreadyExists,
	ErrProjectMemberRoleInvalid: connect.CodeInvalidArgument,
	ErrProjectNameExists:        connect.CodeAlreadyExists,
	ErrProjectAccessDenied:      connect.CodePermissionDenied,
	ErrProjectArchived:          connect.CodeFailedPrecondition,
	ErrProjectHasRunningTasks:   connect.CodeFailedPrecondition,
	ErrProjectNoAvailableNodes:  connect.CodeFailedPrecondition,

	// ASSET
	ErrAssetNotFound:          connect.CodeNotFound,
	ErrAssetDuplicate:         connect.CodeAlreadyExists,
	ErrAssetTypeInvalid:       connect.CodeInvalidArgument,
	ErrAssetNaturalKeyInvalid: connect.CodeInvalidArgument,
	ErrAssetTypeNotManual:     connect.CodeInvalidArgument,
	ErrAssetVersionConflict:   connect.CodeAborted,

	// TASK
	ErrTaskNotFound:         connect.CodeNotFound,
	ErrTaskRunNotFound:      connect.CodeNotFound,
	ErrTaskNameExists:       connect.CodeAlreadyExists,
	ErrTaskInvalidState:     connect.CodeFailedPrecondition,
	ErrTaskNoTargets:        connect.CodeInvalidArgument,
	ErrTaskTemplateNotFound: connect.CodeNotFound,
	ErrTaskCronInvalid:      connect.CodeInvalidArgument,
	ErrTaskProxyInvalid:     connect.CodeInvalidArgument,
	ErrTaskNodeNotAvailable: connect.CodeFailedPrecondition,
	ErrTaskPluginInvalid:    connect.CodeInvalidArgument,

	// NODE
	ErrNodeNotFound:                 connect.CodeNotFound,
	ErrNodeNameExists:               connect.CodeAlreadyExists,
	ErrNodeOffline:                  connect.CodeUnavailable,
	ErrNodeRegistrationTokenInvalid: connect.CodeUnauthenticated,
	ErrNodeRegistrationTokenExpired: connect.CodeUnauthenticated,
	ErrNodeCertExpired:              connect.CodeUnauthenticated,
	ErrNodeCertRevoked:              connect.CodeUnauthenticated,
	ErrNodeHasRunningTasks:          connect.CodeFailedPrecondition,
	ErrNodeUpgradeFailed:            connect.CodeInternal,

	// PLUGIN
	ErrPluginNotFound:                   connect.CodeNotFound,
	ErrPluginSlugVersionExists:          connect.CodeAlreadyExists,
	ErrPluginInvalidFormat:              connect.CodeInvalidArgument,
	ErrPluginTierInvalid:                connect.CodeInvalidArgument,
	ErrPluginBinaryChecksumMismatch:     connect.CodeInvalidArgument,
	ErrPluginPrivilegeNotApproved:       connect.CodePermissionDenied,
	ErrPluginPrivilegeNotPending:        connect.CodeFailedPrecondition,
	ErrPluginPrivilegeUnknown:           connect.CodeInvalidArgument,
	ErrPluginPrivilegePartialNotAllowed: connect.CodeInvalidArgument,
	ErrPluginPrivilegeTampered:          connect.CodeUnauthenticated,
	ErrPluginPrivilegeRejected:          connect.CodePermissionDenied,
	ErrPluginParamsInvalid:              connect.CodeInvalidArgument,
	ErrPluginInstallationFailed:         connect.CodeInternal,
	ErrPluginUpgradeBackwards:           connect.CodeInvalidArgument,
	ErrPluginInUse:                      connect.CodeFailedPrecondition,
	ErrPluginPlatformMismatch:           connect.CodeInvalidArgument,
	ErrPluginConfirmMismatch:            connect.CodeInvalidArgument,
	ErrPluginInactive:                   connect.CodeFailedPrecondition,
	ErrPluginNotInCache:                 connect.CodeNotFound,
	ErrPluginDownload:                   connect.CodeUnavailable,
	ErrPluginHandshakeFailed:            connect.CodeInternal,
	ErrPluginUnavailable:                connect.CodeUnavailable,
	ErrPluginCapabilityViolation:        connect.CodePermissionDenied,
	ErrPluginActivate:                   connect.CodeInternal,

	// NOTIFY
	ErrChannelNotFound:    connect.CodeNotFound,
	ErrChannelURLInvalid:  connect.CodeInvalidArgument,
	ErrChannelTypeInvalid: connect.CodeInvalidArgument,
	ErrChannelTestFailed:  connect.CodeInternal,
	ErrDeliveryNotFound:   connect.CodeNotFound,

	// AUDIT
	ErrAuditLogNotFound:          connect.CodeNotFound,
	ErrAuditChainBroken:          connect.CodeDataLoss,
	ErrAuditVerificationRunning:  connect.CodeFailedPrecondition,
	ErrAuditVerificationNotFound: connect.CodeNotFound,

	// REPORT
	ErrReportNotFound:         connect.CodeNotFound,
	ErrReportGenerationFailed: connect.CodeInternal,
	ErrReportExpired:          connect.CodeNotFound,
	ErrReportTooLarge:         connect.CodeResourceExhausted,

	// EVENT
	ErrEventNotFound: connect.CodeNotFound,

	// CONFIG
	ErrConfigLockedByEnv:      connect.CodeFailedPrecondition,
	ErrConfigValidationFailed: connect.CodeInvalidArgument,

	// CRYPTO
	ErrCryptoEncryptionFailed:   connect.CodeInternal,
	ErrCryptoDecryptionFailed:   connect.CodeInternal,
	ErrCryptoKeyRotationRunning: connect.CodeFailedPrecondition,
	ErrCryptoKeyNotFound:        connect.CodeNotFound,

	// DIRECT
	ErrInternalCallForbidden: connect.CodePermissionDenied,

	// BOOTSTRAP / RUNTIME
	// BOOTSTRAP_* 不应到达 RPC 层；映射为 Internal 仅作防御。
	ErrBootstrapCryptoInvalid:     connect.CodeInternal,
	ErrBootstrapKeyReuseForbidden: connect.CodeInternal,
	ErrBootstrapConfigInvalid:     connect.CodeInternal,
	ErrBootstrapDBUnreachable:     connect.CodeInternal,
	ErrBootstrapPKIInvalid:        connect.CodeInternal,
	ErrBootstrapStorageMissing:    connect.CodeInternal,
	ErrBootstrapGuardViolation:    connect.CodeInternal,
	ErrRuntimeSandboxUnavailable:  connect.CodeUnavailable,
	ErrMetricsUnavailable:         connect.CodeUnavailable,
}

// connectCodeFor 查询 Code 对应的 connect.Code。
// 未注册的 Code 返回 CodeUnknown（防御性兜底；正常情况下不会触发，
// 因为所有 Code 都在 codes.go AllCodes 里且测试覆盖每条映射）。
func connectCodeFor(code Code) connect.Code {
	if c, ok := codeToConnect[code]; ok {
		return c
	}
	return connect.CodeUnknown
}
