package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/platform/audithook"
)

// === stubs ===

type stubAuth struct {
	principal *auth.UserPrincipal
	err       error
}

func (s *stubAuth) AuthenticateBearer(_ context.Context, _ string) (*auth.UserPrincipal, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.principal, nil
}

type stubMember struct {
	ids []string
	err error
}

func (s *stubMember) ListProjectIDsByUser(_ context.Context, _ string) ([]string, error) {
	return s.ids, s.err
}

type stubResource struct {
	name string
	cols []string
	rows []Row
	// 记录最近一次 stream 收到的 scope，便于断言 RBAC 注入
	lastScope Scope
	err       error
}

func (s *stubResource) Name() string      { return s.name }
func (s *stubResource) Columns() []string { return s.cols }
func (s *stubResource) Stream(_ context.Context, scope Scope, emit func(Row) error) error {
	s.lastScope = scope
	if s.err != nil {
		return s.err
	}
	for _, r := range s.rows {
		if err := emit(r); err != nil {
			return err
		}
	}
	return nil
}

type recordAudit struct {
	events []audithook.Event
}

func (r *recordAudit) Log(_ context.Context, ev audithook.Event) error {
	r.events = append(r.events, ev)
	return nil
}

func newHandlerWithSA(t *testing.T, resource *stubResource) (*Handler, *recordAudit) {
	t.Helper()
	a := &stubAuth{principal: &auth.UserPrincipal{
		UserID: "u-sa", TenantID: "t1", Username: "sa", Role: identitydomain.RoleSuperAdmin,
	}}
	ra := &recordAudit{}
	h := New(a, nil, nil).Register(resource, "test_export").WithAudit(ra)
	return h, ra
}

func mustGET(t *testing.T, h *Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer fake-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// === Format negotiation ===

func TestHandler_DefaultsToCSV(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}, {"2"}}}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/items")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/csv")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), `attachment; filename="items-`)
	body := rec.Body.String()
	assert.Contains(t, body, "id\n")
	assert.Contains(t, body, "1\n")
	assert.Contains(t, body, "2\n")
}

func TestHandler_FormatJSON(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id", "name"}, rows: []Row{{"1", "alpha"}, {"2", "beta"}}}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/items?format=json")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
	var parsed []map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &parsed))
	require.Len(t, parsed, 2)
	assert.Equal(t, "alpha", parsed[0]["name"])
}

func TestHandler_InvalidFormat_400(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/items?format=parquet")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "INVALID_FORMAT")
}

// TestHandler_FormatXLSX 端到端：响应是有效 .xlsx，包含 header + 数据行。
func TestHandler_FormatXLSX(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id", "name"}, rows: []Row{{"1", "alpha"}, {"2", "beta"}}}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/items?format=xlsx")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "spreadsheetml.sheet")
	assert.Contains(t, rec.Header().Get("Content-Disposition"), ".xlsx")

	xf, err := excelize.OpenReader(bytes.NewReader(rec.Body.Bytes()))
	require.NoError(t, err)
	defer xf.Close()
	rows, err := xf.GetRows("Sheet1")
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, []string{"id", "name"}, rows[0])
	assert.Equal(t, []string{"1", "alpha"}, rows[1])
}

// === Auth ===

func TestHandler_MissingAuth_401(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	a := &stubAuth{principal: &auth.UserPrincipal{Role: identitydomain.RoleSuperAdmin}}
	h := New(a, nil, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandler_AuthFails_401WithDomainCode(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	a := &stubAuth{err: errx.New(errx.ErrAuthTokenExpired, "expired")}
	h := New(a, nil, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "AUTH_TOKEN_EXPIRED")
}

// === RBAC scope ===

func TestHandler_SA_NoScopeRestriction(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}}}
	h, _ := newHandlerWithSA(t, res)
	mustGET(t, h, "/api/v1/export/items")
	assert.Empty(t, res.lastScope.TenantID, "SA scope.TenantID 应为空")
	assert.Nil(t, res.lastScope.ProjectIDs, "SA scope.ProjectIDs 应 nil（不限）")
}

func TestHandler_TenantAuditor_ScopedToTenant(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}}}
	a := &stubAuth{principal: &auth.UserPrincipal{
		UserID: "u", TenantID: "t1", Username: "ta", Role: identitydomain.RoleTenantAuditor,
	}}
	h := New(a, nil, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "t1", res.lastScope.TenantID)
	assert.Nil(t, res.lastScope.ProjectIDs)
}

func TestHandler_PA_ScopedToProjectIDs(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}}}
	a := &stubAuth{principal: &auth.UserPrincipal{
		UserID: "u", TenantID: "t1", Username: "pa", Role: identitydomain.RoleProjectAdmin,
	}}
	m := &stubMember{ids: []string{"p1", "p2"}}
	h := New(a, m, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "t1", res.lastScope.TenantID)
	assert.Equal(t, []string{"p1", "p2"}, res.lastScope.ProjectIDs)
}

func TestHandler_PA_NoMemberDB_500(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	a := &stubAuth{principal: &auth.UserPrincipal{
		UserID: "u", TenantID: "t1", Username: "pa", Role: identitydomain.RoleProjectAdmin,
	}}
	// memberDB 为 nil；PA 必须有
	h := New(a, nil, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandler_PA_ZeroProjects_EmptyOutput(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}}}
	a := &stubAuth{principal: &auth.UserPrincipal{
		UserID: "u", TenantID: "t1", Username: "pa", Role: identitydomain.RoleProjectAdmin,
	}}
	m := &stubMember{ids: nil}
	h := New(a, m, nil).Register(res, "test_export")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export/items?format=json", nil)
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{}, res.lastScope.ProjectIDs, "PA 0 项目应传空切片")
}

// === Resource not found ===

func TestHandler_UnknownResource_404(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/nonexistent")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// === Method ===

func TestHandler_POST_405(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}}
	h, _ := newHandlerWithSA(t, res)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/export/items", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// === Audit ===

func TestHandler_LogsAuditOnSuccess(t *testing.T) {
	res := &stubResource{name: "items", cols: []string{"id"}, rows: []Row{{"1"}, {"2"}, {"3"}}}
	h, ra := newHandlerWithSA(t, res)
	mustGET(t, h, "/api/v1/export/items?format=json&project_id=p1")
	require.Len(t, ra.events, 1)
	ev := ra.events[0]
	assert.Equal(t, "test_export", ev.Action)
	assert.Equal(t, "items", ev.ResourceKind)
	assert.Equal(t, "u-sa", ev.ActorUserID)
	assert.Equal(t, "json", ev.Payload["format"])
	assert.Equal(t, 3, ev.Payload["count"])
}

// === Streaming error path ===

func TestHandler_ResourceStreamError_TruncatesGracefully(t *testing.T) {
	res := &stubResource{
		name: "items", cols: []string{"id"},
		err: errors.New("db boom"),
	}
	h, _ := newHandlerWithSA(t, res)
	rec := mustGET(t, h, "/api/v1/export/items?format=csv")
	// header 已写出 → status 200；body 只有 header
	assert.Equal(t, http.StatusOK, rec.Code)
	// body 至少有 BOM + header；不应包含数据行
	body, _ := io.ReadAll(rec.Body)
	assert.Contains(t, string(body), "id")
}
