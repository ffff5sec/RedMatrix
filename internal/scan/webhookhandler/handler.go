// Package webhookhandler 提供 HTTP webhook 入站端点（PR-S32）。
//
// 外部系统（CI/CD / SOAR / 巡检脚本）用 API Key 触发 suite 运行：
//
//	POST /api/v1/webhook/run-suite
//	X-RedMatrix-API-Key: rmk_xxx
//	Content-Type: application/json
//
//	{"suite_id":"<uuid>", "project_id":"<uuid>", "targets":["..."]?}
//
// 成功 200 → {"run_id": "<uuid>"}
// 失败    → {"error": "CODE", "message": "..."}
//
// 与 ConnectRPC RunScanSuite 等价；但走轻量 JSON 端点便于 curl / shell 集成。
package webhookhandler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// MembershipLookup PA 路径专用。
type MembershipLookup interface {
	ListProjectIDsByUser(ctx context.Context, userID string) ([]string, error)
}

// ScanSvc webhook 使用的最小 scan.Service 子集（便于测试）。
type ScanSvc interface {
	GetSuite(ctx context.Context, id string) (*scandomain.ScanSuite, error)
	RunSuite(ctx context.Context, req scan.RunSuiteRequest) (*scandomain.ScanSuiteRun, error)
}

// AuthSvc webhook 使用的最小 auth.Service 子集。
type AuthSvc interface {
	AuthenticateBearer(ctx context.Context, raw string) (*auth.UserPrincipal, error)
}

// Handler 处理 webhook POST。
type Handler struct {
	authSvc  AuthSvc
	scanSvc  ScanSvc
	memberDB MembershipLookup
	logger   *log.Logger
}

// New 构造 handler；authSvc + scanSvc 必填；memberDB 可空（无 PA RBAC 校验时）。
func New(authSvc AuthSvc, scanSvc ScanSvc, memberDB MembershipLookup, logger *log.Logger) (*Handler, error) {
	if authSvc == nil || scanSvc == nil {
		return nil, errx.New(errx.ErrInternal, "webhookhandler.New: authSvc / scanSvc 不能为 nil")
	}
	return &Handler{authSvc: authSvc, scanSvc: scanSvc, memberDB: memberDB, logger: logger}, nil
}

// Path webhook endpoint 路径前缀。注册到 mux 时绑 Path()。
func Path() string { return "/api/v1/webhook/run-suite" }

// runSuiteRequest webhook body。
type runSuiteRequest struct {
	SuiteID   string   `json:"suite_id"`
	ProjectID string   `json:"project_id"`
	Targets   []string `json:"targets,omitempty"`
}

// runSuiteResponse 成功响应。
type runSuiteResponse struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
}

// errorResponse 失败响应。
type errorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// ServeHTTP 入口。仅接受 POST。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "仅支持 POST")
		return
	}

	// 1. 鉴权 - 从 header 提取 API key
	apiKey := strings.TrimSpace(r.Header.Get("X-RedMatrix-API-Key"))
	if apiKey == "" {
		// 兼容 Authorization: Bearer rmk_xxx
		authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimSpace(authHeader[len("Bearer "):])
		}
	}
	if apiKey == "" {
		writeError(w, http.StatusUnauthorized, "AUTH_MISSING", "缺 X-RedMatrix-API-Key header")
		return
	}

	principal, err := h.authSvc.AuthenticateBearer(r.Context(), apiKey)
	if err != nil {
		code, msg := errFields(err)
		writeError(w, http.StatusUnauthorized, code, msg)
		return
	}

	// 2. 解析 body
	var req runSuiteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)) // 64 KiB 上限
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", "JSON 解析失败: "+err.Error())
		return
	}
	if strings.TrimSpace(req.SuiteID) == "" {
		writeError(w, http.StatusBadRequest, "MISSING_SUITE_ID", "suite_id 必填")
		return
	}
	if strings.TrimSpace(req.ProjectID) == "" {
		writeError(w, http.StatusBadRequest, "MISSING_PROJECT_ID", "project_id 必填")
		return
	}

	// 3. RBAC - PA 必须是 project member
	if principal.Role == identitydomain.RoleProjectAdmin {
		if h.memberDB == nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", "PA 路径需 memberDB")
			return
		}
		ids, err := h.memberDB.ListProjectIDsByUser(r.Context(), principal.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
			return
		}
		found := false
		for _, pid := range ids {
			if pid == req.ProjectID {
				found = true
				break
			}
		}
		if !found {
			writeError(w, http.StatusForbidden, "NOT_PROJECT_MEMBER",
				"未加入该 project")
			return
		}
	}

	// 4. targets 为空 → 让 RunSuite 走 suite.default_targets 路径
	// 实际 RunSuite 现在要求 targets ≥ 1；空时回退到 GetSuite 拿 default_targets
	targets := req.Targets
	if len(targets) == 0 {
		suite, err := h.scanSvc.GetSuite(r.Context(), req.SuiteID)
		if err != nil {
			code, msg := errFields(err)
			writeError(w, statusFromCode(code), code, msg)
			return
		}
		if len(suite.DefaultTargets) == 0 {
			writeError(w, http.StatusBadRequest, "MISSING_TARGETS",
				"targets 留空时 suite 必须配置 default_targets")
			return
		}
		targets = append([]string(nil), suite.DefaultTargets...)
	}

	// 5. 调 RunSuite
	run, err := h.scanSvc.RunSuite(r.Context(), scan.RunSuiteRequest{
		SuiteID:   req.SuiteID,
		ProjectID: req.ProjectID,
		Targets:   targets,
		CreatedBy: principal.UserID,
	})
	if err != nil {
		code, msg := errFields(err)
		writeError(w, statusFromCode(code), code, msg)
		return
	}

	if h.logger != nil {
		h.logger.Info("webhook: suite triggered",
			"suite_id", req.SuiteID, "project_id", req.ProjectID,
			"actor_user", principal.UserID, "run_id", run.ID,
			"targets", len(targets))
	}

	writeJSON(w, http.StatusOK, runSuiteResponse{
		RunID:  run.ID,
		Status: string(run.Status),
	})
}

// errFields 提 DomainError 的 Code + Message；非 DomainError → "INTERNAL"。
func errFields(err error) (code, message string) {
	if err == nil {
		return "", ""
	}
	var de *errx.DomainError
	if errors.As(err, &de) {
		return string(de.Code), de.Message
	}
	return "INTERNAL", err.Error()
}

// statusFromCode 把 errx Code 映射成 HTTP status；未识别 → 500。
func statusFromCode(code string) int {
	switch code {
	case "AUTH_FAILED", "AUTH_TOKEN_INVALID", "AUTH_TOKEN_EXPIRED", "AUTH_API_KEY_REVOKED":
		return http.StatusUnauthorized
	case "AUTHZ_FORBIDDEN", "AUTHZ_NOT_PROJECT_MEMBER", "PROJECT_ACCESS_DENIED":
		return http.StatusForbidden
	case "TASK_NOT_FOUND", "PROJECT_NOT_FOUND":
		return http.StatusNotFound
	case "INVALID_INPUT", "MISSING_FIELD", "INVALID_FORMAT",
		"VALIDATION_FAILED", "TASK_NO_TARGETS":
		return http.StatusBadRequest
	case "PROJECT_ARCHIVED":
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Error: code, Message: message})
}
