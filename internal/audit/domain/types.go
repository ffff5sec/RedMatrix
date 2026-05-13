// Package domain audit 模块的领域类型（PR-S33）。
//
// 设计：每条 audit 行携带 prev_hash + hash，构成 per-tenant 单链；
// 校验时扫一段连续行重算 hash，任一行被改 → 后续断链。
package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// GenesisPrevHash 首条 audit 的 prev_hash 占位（64 个 '0'）。
const GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"

// ActionKind 审计事件类型。
type ActionKind string

const (
	// identity
	ActionLogin           ActionKind = "login"
	ActionLogout          ActionKind = "logout"
	ActionLogoutAll       ActionKind = "logout_all" // PR-S41
	ActionPasswordChanged ActionKind = "password_changed"
	ActionAPIKeyCreated   ActionKind = "api_key_created"
	ActionAPIKeyRevoked   ActionKind = "api_key_revoked"
	// identity / SA 账户管理（PR-S41）
	ActionUserCreated   ActionKind = "user_created"
	ActionUserEnabled   ActionKind = "user_enabled"
	ActionUserDisabled  ActionKind = "user_disabled"
	ActionPasswordReset ActionKind = "password_reset"
	ActionForceLogout   ActionKind = "force_logout"

	// scan
	ActionTaskCreate ActionKind = "task_create"
	ActionTaskCancel ActionKind = "task_cancel"
	ActionTaskDelete ActionKind = "task_delete"
	ActionSuiteRun   ActionKind = "suite_run"

	// finding
	ActionFindingTransition ActionKind = "finding_transition"
	ActionFindingComment    ActionKind = "finding_comment"
	ActionFindingAssign     ActionKind = "finding_assign" // PR-S38

	// tenancy（PR-S41）
	ActionProjectCreated       ActionKind = "project_created"
	ActionProjectArchived      ActionKind = "project_archived"
	ActionProjectUnarchived    ActionKind = "project_unarchived"
	ActionProjectDeleted       ActionKind = "project_deleted"
	ActionProjectMemberAdded   ActionKind = "project_member_added"
	ActionProjectMemberRemoved ActionKind = "project_member_removed"

	// pluginpkg / notify
	ActionPluginUploaded   ActionKind = "plugin_uploaded"
	ActionNotifySubCreated ActionKind = "notify_sub_created"
	ActionNotifySubUpdated ActionKind = "notify_sub_updated" // PR-S41
	ActionNotifySubDeleted ActionKind = "notify_sub_deleted" // PR-S41
	ActionNotifySubTested  ActionKind = "notify_sub_tested"  // PR-S41
)

// Valid 判定 action 合法。
func (a ActionKind) Valid() bool {
	switch a {
	case ActionLogin, ActionLogout, ActionLogoutAll, ActionPasswordChanged,
		ActionAPIKeyCreated, ActionAPIKeyRevoked,
		ActionUserCreated, ActionUserEnabled, ActionUserDisabled,
		ActionPasswordReset, ActionForceLogout,
		ActionTaskCreate, ActionTaskCancel, ActionTaskDelete, ActionSuiteRun,
		ActionFindingTransition, ActionFindingComment, ActionFindingAssign,
		ActionProjectCreated, ActionProjectArchived, ActionProjectUnarchived,
		ActionProjectDeleted, ActionProjectMemberAdded, ActionProjectMemberRemoved,
		ActionPluginUploaded, ActionNotifySubCreated,
		ActionNotifySubUpdated, ActionNotifySubDeleted, ActionNotifySubTested:
		return true
	}
	return false
}

// ResourceKind 审计的资源类型。仅文本标识，无强枚举校验。
type ResourceKind = string

// AuditLog 单条审计记录。
type AuditLog struct {
	ID            string
	ActorUserID   *string
	ActorUsername string
	ActorIP       string
	UserAgent     string
	Action        ActionKind
	ResourceKind  ResourceKind
	ResourceID    string
	TenantID      string
	ProjectID     *string
	Payload       map[string]any
	PrevHash      string
	Hash          string
	CreatedAt     time.Time
}

// ValidateForCreate INSERT 前校验。
func (a *AuditLog) ValidateForCreate() error {
	if a == nil {
		return errx.New(errx.ErrInvalidInput, "audit is nil")
	}
	if strings.TrimSpace(a.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "audit.tenant_id 不能为空")
	}
	if !a.Action.Valid() {
		return errx.New(errx.ErrInvalidInput, "audit.action 不合法").
			WithFields("got", string(a.Action))
	}
	if strings.TrimSpace(a.ResourceKind) == "" {
		return errx.New(errx.ErrInvalidInput, "audit.resource_kind 不能为空")
	}
	if !validSHA256Hex(a.PrevHash) {
		return errx.New(errx.ErrInvalidInput, "audit.prev_hash 不是合法 hex").
			WithFields("len", len(a.PrevHash))
	}
	if !validSHA256Hex(a.Hash) {
		return errx.New(errx.ErrInvalidInput, "audit.hash 不是合法 hex").
			WithFields("len", len(a.Hash))
	}
	if a.Payload == nil {
		a.Payload = map[string]any{}
	}
	return nil
}

// ComputeHash 算行 hash：sha256(canonical(...))。
//
// canonical 形态："prev|tenant|action|resource_kind|resource_id|actor_user|actor_username|project|payload-json|ts(unix-nano)"
// payload 用 json.Marshal 保证 key 排序（Go 标准库已排序 map keys）。
func ComputeHash(
	prevHash, tenantID string,
	action ActionKind, resourceKind, resourceID string,
	actorUserID, actorUsername string,
	projectID string,
	payload map[string]any,
	createdAt time.Time,
) string {
	if payload == nil {
		payload = map[string]any{}
	}
	pj, _ := json.Marshal(payload)
	parts := []string{
		prevHash,
		tenantID,
		string(action),
		resourceKind,
		resourceID,
		actorUserID,
		actorUsername,
		projectID,
		string(pj),
		createdAt.UTC().Format(time.RFC3339Nano),
	}
	joined := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(joined))
	return hex.EncodeToString(sum[:])
}

// ComputeForLog 算 a.Hash 并填回；不改其它字段。
func ComputeForLog(a *AuditLog, prevHash string) {
	if a == nil {
		return
	}
	var actor string
	if a.ActorUserID != nil {
		actor = *a.ActorUserID
	}
	var project string
	if a.ProjectID != nil {
		project = *a.ProjectID
	}
	a.PrevHash = prevHash
	a.Hash = ComputeHash(
		prevHash, a.TenantID, a.Action, a.ResourceKind, a.ResourceID,
		actor, a.ActorUsername, project,
		a.Payload, a.CreatedAt,
	)
}

// VerifyChainSegment 校验连续切片：每行的 hash 必须等于按前一行 hash 重算。
// 入参按 created_at ASC 排好；首行允许 prev_hash 任意（caller 决定是否额外校）。
// 返：(ok, breakAt) — ok=true 通过；ok=false 时 breakAt = 第一个不连续行 index。
func VerifyChainSegment(rows []*AuditLog) (bool, int) {
	for i, r := range rows {
		if i > 0 && r.PrevHash != rows[i-1].Hash {
			return false, i
		}
		var actor string
		if r.ActorUserID != nil {
			actor = *r.ActorUserID
		}
		var project string
		if r.ProjectID != nil {
			project = *r.ProjectID
		}
		expected := ComputeHash(
			r.PrevHash, r.TenantID, r.Action, r.ResourceKind, r.ResourceID,
			actor, r.ActorUsername, project,
			r.Payload, r.CreatedAt,
		)
		if expected != r.Hash {
			return false, i
		}
	}
	return true, -1
}

func validSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
