package webhookhandler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/scan"
	scandomain "github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// === stubs ===

type stubAuth struct {
	principal *auth.UserPrincipal
	err       error
	calls     []string
}

func (s *stubAuth) AuthenticateBearer(_ context.Context, raw string) (*auth.UserPrincipal, error) {
	s.calls = append(s.calls, raw)
	if s.err != nil {
		return nil, s.err
	}
	return s.principal, nil
}

type stubScan struct {
	suite      *scandomain.ScanSuite
	suiteErr   error
	run        *scandomain.ScanSuiteRun
	runErr     error
	runRequest *scan.RunSuiteRequest // last seen
}

func (s *stubScan) GetSuite(_ context.Context, _ string) (*scandomain.ScanSuite, error) {
	if s.suiteErr != nil {
		return nil, s.suiteErr
	}
	return s.suite, nil
}
func (s *stubScan) RunSuite(_ context.Context, req scan.RunSuiteRequest) (*scandomain.ScanSuiteRun, error) {
	r := req
	s.runRequest = &r
	if s.runErr != nil {
		return nil, s.runErr
	}
	return s.run, nil
}

type stubMember struct {
	projects []string
	err      error
}

func (m *stubMember) ListProjectIDsByUser(_ context.Context, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.projects, nil
}

// === helpers ===

func newReq(body any, key string) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/webhook/run-suite", bytes.NewReader(b))
	if key != "" {
		r.Header.Set("X-RedMatrix-API-Key", key)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	out := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, w.Body.String())
	}
	return out
}

// === Tests ===

func TestWebhook_MethodGet_Refused(t *testing.T) {
	h, _ := New(&stubAuth{}, &stubScan{}, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/webhook/run-suite", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("want 405, got %d", w.Code)
	}
}

func TestWebhook_MissingKey_401(t *testing.T) {
	h, _ := New(&stubAuth{}, &stubScan{}, nil, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]string{"suite_id": "x", "project_id": "y"}, ""))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestWebhook_AuthFail_401(t *testing.T) {
	h, _ := New(&stubAuth{err: errx.New(errx.ErrAuthFailed, "bad key")}, &stubScan{}, nil, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]string{"suite_id": "x", "project_id": "y"}, "rmk_bad"))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
	body := decodeBody(t, w)
	if body["error"] != "AUTH_FAILED" {
		t.Errorf("want AUTH_FAILED, got %v", body["error"])
	}
}

func TestWebhook_BadBody_400(t *testing.T) {
	h, _ := New(&stubAuth{principal: &auth.UserPrincipal{Role: identitydomain.RoleSuperAdmin}}, &stubScan{}, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	r.Header.Set("X-RedMatrix-API-Key", "rmk_x")
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestWebhook_MissingSuiteID_400(t *testing.T) {
	h, _ := New(&stubAuth{principal: &auth.UserPrincipal{Role: identitydomain.RoleSuperAdmin}}, &stubScan{}, nil, nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]any{"project_id": "p"}, "rmk_x"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestWebhook_PA_NotMember_403(t *testing.T) {
	h, _ := New(
		&stubAuth{principal: &auth.UserPrincipal{UserID: "u1", Role: identitydomain.RoleProjectAdmin}},
		&stubScan{},
		&stubMember{projects: []string{"other-proj"}},
		nil,
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]any{
		"suite_id": "s1", "project_id": "target-proj", "targets": []string{"x"},
	}, "rmk_x"))
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d (body=%s)", w.Code, w.Body.String())
	}
}

func TestWebhook_PA_Member_200(t *testing.T) {
	h, _ := New(
		&stubAuth{principal: &auth.UserPrincipal{UserID: "u1", Role: identitydomain.RoleProjectAdmin}},
		&stubScan{run: &scandomain.ScanSuiteRun{ID: "run-1", Status: scandomain.SuiteRunPending}},
		&stubMember{projects: []string{"target-proj"}},
		nil,
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]any{
		"suite_id": "s1", "project_id": "target-proj", "targets": []string{"x"},
	}, "rmk_x"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if body["run_id"] != "run-1" {
		t.Errorf("want run_id=run-1, got %v", body["run_id"])
	}
}

func TestWebhook_SA_TargetsFromSuite(t *testing.T) {
	stub := &stubScan{
		suite: &scandomain.ScanSuite{
			ID: "s1", DefaultTargets: []string{"a.com", "b.com"},
		},
		run: &scandomain.ScanSuiteRun{ID: "run-1"},
	}
	h, _ := New(
		&stubAuth{principal: &auth.UserPrincipal{UserID: "u1", Role: identitydomain.RoleSuperAdmin}},
		stub, nil, nil,
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]any{
		"suite_id": "s1", "project_id": "p1",
		// targets 缺失 → 取 suite.default_targets
	}, "rmk_x"))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", w.Code, w.Body.String())
	}
	if stub.runRequest == nil || len(stub.runRequest.Targets) != 2 {
		t.Errorf("want targets=2 from default, got %v", stub.runRequest)
	}
}

func TestWebhook_SA_MissingTargets_AndNoDefault_400(t *testing.T) {
	stub := &stubScan{
		suite: &scandomain.ScanSuite{ID: "s1", DefaultTargets: []string{}},
	}
	h, _ := New(
		&stubAuth{principal: &auth.UserPrincipal{UserID: "u1", Role: identitydomain.RoleSuperAdmin}},
		stub, nil, nil,
	)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, newReq(map[string]any{
		"suite_id": "s1", "project_id": "p1",
	}, "rmk_x"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestWebhook_BearerHeader(t *testing.T) {
	stubA := &stubAuth{principal: &auth.UserPrincipal{Role: identitydomain.RoleSuperAdmin}}
	h, _ := New(stubA, &stubScan{run: &scandomain.ScanSuiteRun{ID: "run-1"}}, nil, nil)

	b, _ := json.Marshal(map[string]any{"suite_id": "s", "project_id": "p", "targets": []string{"x"}})
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(b))
	r.Header.Set("Authorization", "Bearer rmk_via_bearer")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	if len(stubA.calls) != 1 || stubA.calls[0] != "rmk_via_bearer" {
		t.Errorf("Bearer header 没传给 auth: %v", stubA.calls)
	}
}
