// rbac_test.go 覆盖 PR-S17-RBAC 的 BOLA 收紧：assertTaskAccess /
// assertArtifactKeyAccess 在所有跨租户 / 跨项目 / wire 缺失场景下应正确拒绝
// （task 路径不区分"不存在"与"无权"，返 ErrTaskNotFound；artifact key 路径
// 返 ErrInvalidInput），不泄露存在性，不暴露真实错码。

package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scanv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/scan/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// === stubs ===

// stubScanSvc 是 scan.Service 的最小实现：仅 GetTask 行为可控；
// 其它方法均 panic，强迫测试只覆盖 RBAC 守门关心的代码路径。
type stubScanSvc struct {
	getTaskRes *scandomain.ScanTask
	getTaskErr error
	getTaskID  string
}

func (s *stubScanSvc) CreateTask(_ context.Context, _ scan.CreateTaskRequest) (*scandomain.ScanTask, error) {
	panic("unexpected: CreateTask")
}

func (s *stubScanSvc) ListTasks(_ context.Context, _ scan.ListTasksRequest) (*scan.ListTasksResult, error) {
	panic("unexpected: ListTasks")
}

func (s *stubScanSvc) GetTask(_ context.Context, id string) (*scandomain.ScanTask, error) {
	s.getTaskID = id
	if s.getTaskErr != nil {
		return nil, s.getTaskErr
	}
	return s.getTaskRes, nil
}

func (s *stubScanSvc) CancelTask(_ context.Context, _ string) error {
	panic("unexpected: CancelTask")
}

func (s *stubScanSvc) DeleteTask(_ context.Context, _ string) error {
	panic("unexpected: DeleteTask")
}

func (s *stubScanSvc) ListAssignmentsByTask(_ context.Context, _ string) ([]*scandomain.TaskAssignment, error) {
	panic("unexpected: ListAssignmentsByTask")
}

func (s *stubScanSvc) CountAssignmentsByTaskIDs(_ context.Context, _ []string) (map[string]int, error) {
	panic("unexpected: CountAssignmentsByTaskIDs")
}

func (s *stubScanSvc) PullForNode(_ context.Context, _ string) ([]*scan.PulledAssignment, error) {
	panic("unexpected: PullForNode")
}

func (s *stubScanSvc) UpdateAssignmentProgress(_ context.Context, _, _ string, _ scandomain.AssignmentStatus, _ string) error {
	panic("unexpected: UpdateAssignmentProgress")
}

func (s *stubScanSvc) ReportResults(_ context.Context, _, _ string, _ []scan.ResultItem) error {
	panic("unexpected: ReportResults")
}

func (s *stubScanSvc) ListResultsByTask(_ context.Context, _ string) ([]*scandomain.ScanResult, error) {
	panic("unexpected: ListResultsByTask")
}

func (s *stubScanSvc) SearchResults(_ context.Context, _ scan.SearchRequest) (*scan.SearchResultPage, error) {
	panic("unexpected: SearchResults")
}

func (s *stubScanSvc) TriggerCronTask(_ context.Context, _ string) error {
	panic("unexpected: TriggerCronTask")
}

func (s *stubScanSvc) TriggerCronSuite(_ context.Context, _ string) error {
	panic("unexpected: TriggerCronSuite")
}

func (s *stubScanSvc) SweepStaleAssignments(_ context.Context, _ time.Duration) (int, error) {
	panic("unexpected: SweepStaleAssignments")
}

func (s *stubScanSvc) RetryTask(_ context.Context, _ string) (*scandomain.ScanTask, error) {
	panic("unexpected: RetryTask")
}

func (s *stubScanSvc) GetArtifactDownloadURL(_ context.Context, _ string) (string, time.Time, error) {
	panic("unexpected: GetArtifactDownloadURL")
}

// PR-S23 stubs — handler rbac 测试不覆盖套件 RPC，全 panic（未被调）
func (s *stubScanSvc) CreateSuite(_ context.Context, _ scan.CreateSuiteRequest) (*scandomain.ScanSuite, error) {
	panic("unexpected: CreateSuite")
}
func (s *stubScanSvc) ListSuites(_ context.Context, _ scan.ListSuitesRequest) (*scan.ListSuitesResult, error) {
	panic("unexpected: ListSuites")
}
func (s *stubScanSvc) GetSuite(_ context.Context, _ string) (*scandomain.ScanSuite, error) {
	panic("unexpected: GetSuite")
}
func (s *stubScanSvc) DeleteSuite(_ context.Context, _ string) error {
	panic("unexpected: DeleteSuite")
}
func (s *stubScanSvc) RunSuite(_ context.Context, _ scan.RunSuiteRequest) (*scandomain.ScanSuiteRun, error) {
	panic("unexpected: RunSuite")
}
func (s *stubScanSvc) GetSuiteRun(_ context.Context, _ string) (*scan.SuiteRunDetail, error) {
	panic("unexpected: GetSuiteRun")
}
func (s *stubScanSvc) ListSuiteRuns(_ context.Context, _ scan.ListSuiteRunsRequest) (*scan.ListSuiteRunsResult, error) {
	panic("unexpected: ListSuiteRuns")
}

var _ scan.Service = (*stubScanSvc)(nil)

// stubAuthSvc 是 auth.Service 的最小实现：仅 AuthenticateBearer 行为可控；
// 其它方法均 panic。
type stubAuthSvc struct {
	princ *auth.UserPrincipal
	err   error
}

func (s *stubAuthSvc) Login(_ context.Context, _ auth.LoginRequest) (*auth.LoginResult, error) {
	panic("unexpected: Login")
}

func (s *stubAuthSvc) AuthenticateBearer(_ context.Context, _ string) (*auth.UserPrincipal, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.princ, nil
}

func (s *stubAuthSvc) Logout(_ context.Context, _ string) error {
	panic("unexpected: Logout")
}

func (s *stubAuthSvc) LogoutAllSessions(_ context.Context, _ string) error {
	panic("unexpected: LogoutAllSessions")
}

func (s *stubAuthSvc) CreateAPIKey(_ context.Context, _ auth.CreateAPIKeyRequest) (*auth.CreateAPIKeyResult, error) {
	panic("unexpected: CreateAPIKey")
}

func (s *stubAuthSvc) ListAPIKeys(_ context.Context, _ string) ([]*identitydomain.APIKey, error) {
	panic("unexpected: ListAPIKeys")
}

func (s *stubAuthSvc) RevokeAPIKey(_ context.Context, _, _ string) error {
	panic("unexpected: RevokeAPIKey")
}

func (s *stubAuthSvc) GetCurrentUser(_ context.Context, _ string) (*identitydomain.User, error) {
	panic("unexpected: GetCurrentUser")
}

func (s *stubAuthSvc) ChangePassword(_ context.Context, _, _, _ string) error {
	panic("unexpected: ChangePassword")
}

func (s *stubAuthSvc) CreateUser(_ context.Context, _ auth.CreateUserRequest) (*auth.CreateUserResult, error) {
	panic("unexpected: CreateUser")
}

func (s *stubAuthSvc) ListUsers(_ context.Context, _ auth.ListUsersRequest) (*auth.ListUsersResult, error) {
	panic("unexpected: ListUsers")
}

func (s *stubAuthSvc) GetUser(_ context.Context, _ string) (*identitydomain.User, error) {
	panic("unexpected: GetUser")
}

func (s *stubAuthSvc) EnableUser(_ context.Context, _ string) error {
	panic("unexpected: EnableUser")
}

func (s *stubAuthSvc) DisableUser(_ context.Context, _ string) error {
	panic("unexpected: DisableUser")
}

func (s *stubAuthSvc) ResetPassword(_ context.Context, _ string) (string, error) {
	panic("unexpected: ResetPassword")
}

func (s *stubAuthSvc) ForceLogout(_ context.Context, _ string) error {
	panic("unexpected: ForceLogout")
}

var _ auth.Service = (*stubAuthSvc)(nil)

// stubMemberDB 实现 MembershipLookup：仅返指定 ids 或 error；非空 ids 复制成切片。
type stubMemberDB struct {
	ids       []string
	err       error
	calledFor string // 最近一次调用的 userID
}

func (m *stubMemberDB) ListProjectIDsByUser(_ context.Context, userID string) ([]string, error) {
	m.calledFor = userID
	if m.err != nil {
		return nil, m.err
	}
	if m.ids == nil {
		return nil, nil
	}
	out := make([]string, len(m.ids))
	copy(out, m.ids)
	return out, nil
}

// === helpers ===

// principal 构造 UserPrincipal（其他字段填默认值；测试不关心）。
func principal(role identitydomain.Role, tenantID, userID string) *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID:   userID,
		TenantID: tenantID,
		Username: "tester",
		Role:     role,
		Source:   auth.PrincipalSourceJWT,
	}
}

// task 构造 ScanTask，最小字段（仅 RBAC 路径关心 ID / TenantID / ProjectID）。
func taskFixture(id, tenantID, projectID string) *scandomain.ScanTask {
	return &scandomain.ScanTask{
		ID:        id,
		TenantID:  tenantID,
		ProjectID: projectID,
		Name:      "fixture",
		Kind:      scandomain.KindPortScan,
		Status:    scandomain.TaskPending,
	}
}

// newHandler 构造测试用 Handler（principal / task / memberDB 由 caller 注）。
func newHandler(t *testing.T, princ *auth.UserPrincipal, task *scandomain.ScanTask, taskErr error, mem MembershipLookup) *Handler {
	t.Helper()
	svc := &stubScanSvc{getTaskRes: task, getTaskErr: taskErr}
	authSvc := &stubAuthSvc{princ: princ}
	h, err := New(svc, authSvc, mem)
	require.NoError(t, err)
	return h
}

// authHeaderReq 装一个带 Bearer 的 connect.Request。
func authHeaderReq[T any](msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	r.Header().Set("Authorization", "Bearer x")
	return r
}

// requireConnectCode 断言 err 来自 connect 且 code 命中预期；同时校 errx Code 命中。
func requireConnectCode(t *testing.T, err error, wantConnect connect.Code, wantErrx errx.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, wantConnect, connect.CodeOf(err),
		"connect.Code mismatch: got=%v want=%v err=%v", connect.CodeOf(err), wantConnect, err)
	// toConnectError 把 DomainError.Code 写到 message 头部："<CODE>: <msg>"
	assert.Contains(t, err.Error(), string(wantErrx),
		"errx.Code missing from error: %v", err)
}

// === GetScanTask（assertTaskAccess 路径） ===
//
// 一份 task 在 tenant=T1, project=P1；矩阵覆盖 SA / TA / PA / PlatformAuditor。

const (
	fixtureTaskID    = "task-aaa"
	fixtureTenantID  = "T1"
	fixtureProjectID = "P1"
)

// callGetScanTask 是 GetScanTask 的最小调用 helper：装 req + 调 handler + 返 err。
func callGetScanTask(t *testing.T, h *Handler) error {
	t.Helper()
	_, err := h.GetScanTask(context.Background(),
		authHeaderReq(&scanv1.GetScanTaskRequest{Id: fixtureTaskID}))
	return err
}

func TestAssertTaskAccess_GetScanTask_RBAC(t *testing.T) {
	t.Run("SA cross-tenant OK", func(t *testing.T) {
		p := principal(identitydomain.RoleSuperAdmin, "" /*跨租户*/, "sa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		h := newHandler(t, p, task, nil, nil)

		err := callGetScanTask(t, h)
		assert.NoError(t, err)
	})

	t.Run("PlatformAuditor cross-tenant OK", func(t *testing.T) {
		p := principal(identitydomain.RolePlatformAuditor, "" /*跨租户*/, "pla-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		h := newHandler(t, p, task, nil, nil)

		err := callGetScanTask(t, h)
		assert.NoError(t, err)
	})

	t.Run("TA same tenant OK", func(t *testing.T) {
		p := principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		h := newHandler(t, p, task, nil, nil)

		err := callGetScanTask(t, h)
		assert.NoError(t, err)
	})

	t.Run("TA cross tenant returns TASK_NOT_FOUND not Forbidden", func(t *testing.T) {
		p := principal(identitydomain.RoleTenantAuditor, "T-OTHER", "ta-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		h := newHandler(t, p, task, nil, nil)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
		assert.Contains(t, err.Error(), "task 不存在")
	})

	t.Run("PA same tenant project IN list OK", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		mem := &stubMemberDB{ids: []string{"P-OTHER", fixtureProjectID}}
		h := newHandler(t, p, task, nil, mem)

		err := callGetScanTask(t, h)
		assert.NoError(t, err)
		assert.Equal(t, "pa-1", mem.calledFor)
	})

	t.Run("PA same tenant project NOT in list returns TASK_NOT_FOUND", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		mem := &stubMemberDB{ids: []string{"P-OTHER", "P-ANOTHER"}}
		h := newHandler(t, p, task, nil, mem)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
		assert.Contains(t, err.Error(), "task 不存在")
	})

	t.Run("PA same tenant empty membership returns TASK_NOT_FOUND", func(t *testing.T) {
		// 加入 0 个项目（明确空切片）也应当 NotFound — 防 PA 看到任何 task。
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		mem := &stubMemberDB{ids: []string{}}
		h := newHandler(t, p, task, nil, mem)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
	})

	t.Run("PA cross tenant returns TASK_NOT_FOUND short-circuit", func(t *testing.T) {
		// 跨 tenant 应该在查 memberDB 之前就拒掉（不调 memberDB），
		// 与 TA 的语义一致防枚举。
		p := principal(identitydomain.RoleProjectAdmin, "T-OTHER", "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		mem := &stubMemberDB{ids: []string{fixtureProjectID}}
		h := newHandler(t, p, task, nil, mem)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
		// 跨租户分支应该直接短路，不查 memberDB
		assert.Empty(t, mem.calledFor, "cross-tenant PA must short-circuit before memberDB lookup")
	})

	t.Run("PA but memberDB nil returns Internal", func(t *testing.T) {
		// wire 缺失 — 永远不该到这里，但若发生必须 Internal 不是 NotFound（防遮蔽 bug）。
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		h := newHandler(t, p, task, nil, nil /*memberDB 缺*/)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeInternal, errx.ErrInternal)
	})

	t.Run("PA memberDB returns error propagates", func(t *testing.T) {
		// memberDB 故障应原样上抛（已是 DomainError），不被遮蔽成 NotFound。
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
		dbErr := errx.New(errx.ErrDatabase, "pg 连接异常")
		mem := &stubMemberDB{err: dbErr}
		h := newHandler(t, p, task, nil, mem)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeInternal, errx.ErrDatabase)
	})

	t.Run("GetTask returns NotFound propagates", func(t *testing.T) {
		// task 真不存在时直接返 NotFound（不进 RBAC 分支）。
		p := principal(identitydomain.RoleSuperAdmin, "", "sa-1")
		h := newHandler(t, p, nil,
			errx.New(errx.ErrTaskNotFound, "task 不存在").WithFields("id", fixtureTaskID), nil)

		err := callGetScanTask(t, h)
		requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
	})
}

// === CancelScanTask / DeleteScanTask / RetryScanTask / ListTaskAssignments /
// ListTaskResults 走同一 assertTaskAccess，所以这里抽 helper 做一次 sanity 矩阵
// （SA OK / TA 跨租户 NotFound / PA wire 缺失 Internal）即可。深度由 GetScanTask 套保证。

// rbacOp 描述一个走 assertTaskAccess 的 RPC 调用。
type rbacOp struct {
	name      string
	call      func(t *testing.T, h *Handler) error
	allowedPA bool // 是否对 PA 开放（DeleteScanTask 仅 SA + TA）
}

func rbacOps() []rbacOp {
	return []rbacOp{
		{
			name: "GetScanTask",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.GetScanTask(context.Background(),
					authHeaderReq(&scanv1.GetScanTaskRequest{Id: fixtureTaskID}))
				return err
			},
			allowedPA: true,
		},
		{
			name: "CancelScanTask",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.CancelScanTask(context.Background(),
					authHeaderReq(&scanv1.CancelScanTaskRequest{Id: fixtureTaskID}))
				return err
			},
			allowedPA: true,
		},
		{
			name: "DeleteScanTask",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.DeleteScanTask(context.Background(),
					authHeaderReq(&scanv1.DeleteScanTaskRequest{Id: fixtureTaskID}))
				return err
			},
			allowedPA: false, // SA + TA only（handler RequireRole 收紧）
		},
		{
			name: "RetryScanTask",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.RetryScanTask(context.Background(),
					authHeaderReq(&scanv1.RetryScanTaskRequest{Id: fixtureTaskID}))
				return err
			},
			allowedPA: true,
		},
		{
			name: "ListTaskAssignments",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.ListTaskAssignments(context.Background(),
					authHeaderReq(&scanv1.ListTaskAssignmentsRequest{TaskId: fixtureTaskID}))
				return err
			},
			allowedPA: true,
		},
		{
			name: "ListTaskResults",
			call: func(t *testing.T, h *Handler) error {
				t.Helper()
				_, err := h.ListTaskResults(context.Background(),
					authHeaderReq(&scanv1.ListTaskResultsRequest{TaskId: fixtureTaskID}))
				return err
			},
			allowedPA: true,
		},
	}
}

// TestAssertTaskAccess_AllOps_TACrossTenant 验证所有走 assertTaskAccess 的 RPC
// 在 TA 跨租户时都返 TASK_NOT_FOUND（防枚举）。
func TestAssertTaskAccess_AllOps_TACrossTenant(t *testing.T) {
	for _, op := range rbacOps() {
		t.Run(op.name, func(t *testing.T) {
			p := principal(identitydomain.RoleTenantAuditor, "T-OTHER", "ta-1")
			task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
			// CancelTask / DeleteTask / RetryTask 在 RBAC 失败后不会调 svc 的执行方法，
			// 所以 stub 用 panic 兜底是 OK 的（永远不进入）。
			h := newHandler(t, p, task, nil, nil)

			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodeNotFound, errx.ErrTaskNotFound)
		})
	}
}

// TestAssertTaskAccess_AllOps_PANilMemberDB 验证所有走 assertTaskAccess 的 RPC
// 在 PA wire 缺失 memberDB 时都返 Internal（不是 NotFound）。
// DeleteScanTask 不在此覆盖（PA 不能调 Delete，RequireRole 在 assertTaskAccess
// 之前先拒掉）。
func TestAssertTaskAccess_AllOps_PANilMemberDB(t *testing.T) {
	for _, op := range rbacOps() {
		if !op.allowedPA {
			continue
		}
		t.Run(op.name, func(t *testing.T) {
			p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
			task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
			h := newHandler(t, p, task, nil, nil)

			err := op.call(t, h)
			requireConnectCode(t, err, connect.CodeInternal, errx.ErrInternal)
		})
	}
}

// TestDeleteScanTask_PARejectedByRole 单独验证：PA 调 DeleteScanTask 应被
// RequireRole 拒掉（AUTHZ_ROLE_INSUFFICIENT），与 assertTaskAccess 路径无关。
func TestDeleteScanTask_PARejectedByRole(t *testing.T) {
	p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
	task := taskFixture(fixtureTaskID, fixtureTenantID, fixtureProjectID)
	// 即使 memberDB OK，PA 也应被早期 RequireRole 拦下
	mem := &stubMemberDB{ids: []string{fixtureProjectID}}
	h := newHandler(t, p, task, nil, mem)

	_, err := h.DeleteScanTask(context.Background(),
		authHeaderReq(&scanv1.DeleteScanTaskRequest{Id: fixtureTaskID}))
	requireConnectCode(t, err, connect.CodePermissionDenied, errx.ErrAuthzRoleInsufficient)
}

// === GetArtifactDownloadURL（assertArtifactKeyAccess 路径） ===

// callGetArtifactURL 装 req 并直接调 handler。预期：RBAC 失败时早返；
// 通过时 service.GetArtifactDownloadURL 被调到（stub 会 panic — 因此通过路径
// 用单独 happy path 用例验证，不混在矩阵里）。
func callGetArtifactURL(t *testing.T, h *Handler, key string) error {
	t.Helper()
	_, err := h.GetArtifactDownloadURL(context.Background(),
		authHeaderReq(&scanv1.GetArtifactDownloadURLRequest{Key: key}))
	return err
}

func TestAssertArtifactKeyAccess_RBAC(t *testing.T) {
	// happy path 需要 svc.GetArtifactDownloadURL 不 panic — 用一个能返成功的
	// stub 子类。这里直接覆盖 method 用 ad-hoc Service 不便（panic-only stub）；
	// 改在 stubScanSvc 加可控字段会污染本测试范围。
	// 方案：直接断言"不报 RBAC 错"足够 — RBAC 通过会进 service 路径，stub
	// panic 让 t.Run 失败。所以 SA / PlatformAuditor 的成功用例改用 artifactSvcOK。

	t.Run("SA any prefix OK pass through to svc", func(t *testing.T) {
		p := principal(identitydomain.RoleSuperAdmin, "", "sa-1")
		h := newArtifactHandler(t, p,
			&artifactURLOK{url: "https://example/x", expires: time.Now().Add(time.Minute)})

		_, err := h.GetArtifactDownloadURL(context.Background(),
			authHeaderReq(&scanv1.GetArtifactDownloadURLRequest{Key: "T-OTHER/any-uuid.bin"}))
		assert.NoError(t, err)
	})

	t.Run("PlatformAuditor any prefix OK", func(t *testing.T) {
		p := principal(identitydomain.RolePlatformAuditor, "", "pla-1")
		h := newArtifactHandler(t, p,
			&artifactURLOK{url: "https://example/x", expires: time.Now().Add(time.Minute)})

		_, err := h.GetArtifactDownloadURL(context.Background(),
			authHeaderReq(&scanv1.GetArtifactDownloadURLRequest{Key: "T-OTHER/any-uuid.bin"}))
		assert.NoError(t, err)
	})

	t.Run("TA matching prefix OK", func(t *testing.T) {
		p := principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1")
		h := newArtifactHandler(t, p,
			&artifactURLOK{url: "https://example/x", expires: time.Now().Add(time.Minute)})

		_, err := h.GetArtifactDownloadURL(context.Background(),
			authHeaderReq(&scanv1.GetArtifactDownloadURLRequest{Key: fixtureTenantID + "/abc.bin"}))
		assert.NoError(t, err)
	})

	t.Run("PA matching prefix OK", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		h := newArtifactHandler(t, p,
			&artifactURLOK{url: "https://example/x", expires: time.Now().Add(time.Minute)})

		_, err := h.GetArtifactDownloadURL(context.Background(),
			authHeaderReq(&scanv1.GetArtifactDownloadURLRequest{Key: fixtureTenantID + "/abc.bin"}))
		assert.NoError(t, err)
	})

	t.Run("TA cross-tenant prefix returns InvalidInput", func(t *testing.T) {
		p := principal(identitydomain.RoleTenantAuditor, fixtureTenantID, "ta-1")
		// stub svc 不会被调 — RBAC 在 svc 之前拒
		h := newHandler(t, p, nil, nil, nil)

		err := callGetArtifactURL(t, h, "T-OTHER/uuid.bin")
		requireConnectCode(t, err, connect.CodeInvalidArgument, errx.ErrInvalidInput)
		assert.Contains(t, err.Error(), "无权访问")
	})

	t.Run("PA cross-tenant prefix returns InvalidInput", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, fixtureTenantID, "pa-1")
		h := newHandler(t, p, nil, nil, nil)

		err := callGetArtifactURL(t, h, "T-OTHER/uuid.bin")
		requireConnectCode(t, err, connect.CodeInvalidArgument, errx.ErrInvalidInput)
	})

	t.Run("TA empty tenant principal returns InvalidInput", func(t *testing.T) {
		// 异常 wire 路径 — TA 不该 TenantID 为空，但若发生也必须拒。
		p := principal(identitydomain.RoleTenantAuditor, "" /*异常*/, "ta-1")
		h := newHandler(t, p, nil, nil, nil)

		err := callGetArtifactURL(t, h, "anything/uuid.bin")
		requireConnectCode(t, err, connect.CodeInvalidArgument, errx.ErrInvalidInput)
	})

	t.Run("PA empty tenant principal returns InvalidInput", func(t *testing.T) {
		p := principal(identitydomain.RoleProjectAdmin, "" /*异常*/, "pa-1")
		h := newHandler(t, p, nil, nil, nil)

		err := callGetArtifactURL(t, h, "anything/uuid.bin")
		requireConnectCode(t, err, connect.CodeInvalidArgument, errx.ErrInvalidInput)
	})

	t.Run("TA prefix-only match without slash rejected", func(t *testing.T) {
		// 防"前缀粘连"：T1 不应能拿 T11/x 的 artifact（必须 T1/）
		p := principal(identitydomain.RoleTenantAuditor, "T1", "ta-1")
		h := newHandler(t, p, nil, nil, nil)

		err := callGetArtifactURL(t, h, "T11/uuid.bin")
		requireConnectCode(t, err, connect.CodeInvalidArgument, errx.ErrInvalidInput)
	})
}

// === artifact URL svc stub（仅 GetArtifactDownloadURL 可控） ===

// artifactURLOK 是仅 GetArtifactDownloadURL 行为可控的 scan.Service 子集；
// 其它方法 panic。给 happy path 测试装 svc 用。
type artifactURLOK struct {
	stubScanSvc
	url     string
	expires time.Time
	err     error
}

func (a *artifactURLOK) GetArtifactDownloadURL(_ context.Context, _ string) (string, time.Time, error) {
	if a.err != nil {
		return "", time.Time{}, a.err
	}
	return a.url, a.expires, nil
}

// newArtifactHandler 装一个 GetArtifactDownloadURL 可成功的 handler。
func newArtifactHandler(t *testing.T, princ *auth.UserPrincipal, svc *artifactURLOK) *Handler {
	t.Helper()
	authSvc := &stubAuthSvc{princ: princ}
	h, err := New(svc, authSvc, nil)
	require.NoError(t, err)
	return h
}
