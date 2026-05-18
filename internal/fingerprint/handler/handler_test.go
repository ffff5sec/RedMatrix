package handler

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	fpv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/fingerprint/v1"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/fingerprint"
	"github.com/ffff5sec/RedMatrix/internal/identity/auth"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
)

// === stubs ===

type stubRepo struct {
	rules   []*fingerprint.CustomRule
	created []*fingerprint.CustomRule
	deleted []string
}

func (s *stubRepo) Insert(_ context.Context, r *fingerprint.CustomRule) error {
	// 同名（未软删）冲突
	for _, c := range s.rules {
		if c.Name == r.Name {
			return errx.New(errx.ErrInvalidInput, "同名规则已存在").WithFields("name", r.Name)
		}
	}
	if r.ID == "" {
		r.ID = "r-" + r.Name
	}
	r.CreatedAt = time.Now()
	r.UpdatedAt = r.CreatedAt
	s.rules = append(s.rules, r)
	s.created = append(s.created, r)
	return nil
}
func (s *stubRepo) GetByID(_ context.Context, id string) (*fingerprint.CustomRule, error) {
	for _, c := range s.rules {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, nil
}
func (s *stubRepo) ListEnabledByTenant(_ context.Context, _ string) ([]*fingerprint.CustomRule, error) {
	out := []*fingerprint.CustomRule{}
	for _, c := range s.rules {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}
func (s *stubRepo) ListAllByTenant(_ context.Context, _ string) ([]*fingerprint.CustomRule, error) {
	return append([]*fingerprint.CustomRule(nil), s.rules...), nil
}
func (s *stubRepo) SoftDelete(_ context.Context, id string) error {
	for i, c := range s.rules {
		if c.ID == id {
			s.rules = append(s.rules[:i], s.rules[i+1:]...)
			s.deleted = append(s.deleted, id)
			return nil
		}
	}
	return errx.New(errx.ErrInvalidInput, "not found")
}
func (s *stubRepo) ToggleEnabled(_ context.Context, _ string, _ bool) error { return nil }

type stubAuth struct{ p *auth.UserPrincipal }

func (s *stubAuth) AuthenticateBearer(_ context.Context, _ string) (*auth.UserPrincipal, error) {
	return s.p, nil
}

func saPrincipal() *auth.UserPrincipal {
	return &auth.UserPrincipal{
		UserID: "u-sa", Username: "sa", TenantID: "t1",
		Role: identitydomain.RoleSuperAdmin,
	}
}

func newHandler(t *testing.T) (*Handler, *stubRepo) {
	t.Helper()
	builtin := fingerprint.Default()
	r := &stubRepo{}
	h, err := New(builtin, r, &stubAuth{p: saPrincipal()})
	require.NoError(t, err)
	return h, r
}

// === BulkImport ===

const validYAML = `
rules:
  - name: foo-tool
    fields: [body]
    keyword: foo-banner
  - name: bar-tool
    fields: [title]
    keyword: BAR Console
`

func bulkReq(yaml, policy string) *connect.Request[fpv1.BulkImportCustomRulesRequest] {
	req := connect.NewRequest(&fpv1.BulkImportCustomRulesRequest{
		YamlText:        yaml,
		DuplicatePolicy: policy,
	})
	req.Header().Set("Authorization", "Bearer x")
	return req
}

func TestBulkImport_AllCreated(t *testing.T) {
	h, repo := newHandler(t)
	resp, err := h.BulkImportCustomRules(context.Background(), bulkReq(validYAML, ""))
	require.NoError(t, err)
	assert.EqualValues(t, 2, resp.Msg.Created)
	assert.EqualValues(t, 0, resp.Msg.Skipped)
	assert.EqualValues(t, 0, resp.Msg.Failed)
	assert.Len(t, repo.created, 2)
	assert.Equal(t, "foo-tool", repo.created[0].Name)
}

func TestBulkImport_SkipsDuplicates(t *testing.T) {
	h, repo := newHandler(t)
	// 预置同名
	repo.rules = []*fingerprint.CustomRule{
		{ID: "r-foo-tool", TenantID: "t1", Name: "foo-tool", Keyword: "old"},
	}
	resp, err := h.BulkImportCustomRules(context.Background(), bulkReq(validYAML, "skip"))
	require.NoError(t, err)
	assert.EqualValues(t, 1, resp.Msg.Created) // 只新建 bar
	assert.EqualValues(t, 1, resp.Msg.Skipped) // foo 跳过
	assert.EqualValues(t, 0, resp.Msg.Failed)
}

func TestBulkImport_Overwrite_DeletesOldThenInserts(t *testing.T) {
	h, repo := newHandler(t)
	repo.rules = []*fingerprint.CustomRule{
		{ID: "r-old-foo", TenantID: "t1", Name: "foo-tool", Keyword: "old"},
	}
	resp, err := h.BulkImportCustomRules(context.Background(), bulkReq(validYAML, "overwrite"))
	require.NoError(t, err)
	assert.EqualValues(t, 2, resp.Msg.Created)
	assert.EqualValues(t, 0, resp.Msg.Skipped)
	assert.Contains(t, repo.deleted, "r-old-foo", "overwrite 应先软删旧")
}

func TestBulkImport_EmptyYAMLRejected(t *testing.T) {
	h, _ := newHandler(t)
	_, err := h.BulkImportCustomRules(context.Background(), bulkReq("", ""))
	require.Error(t, err)
}

func TestBulkImport_InvalidPolicyRejected(t *testing.T) {
	h, _ := newHandler(t)
	_, err := h.BulkImportCustomRules(context.Background(), bulkReq(validYAML, "weird"))
	require.Error(t, err)
}

func TestBulkImport_InvalidYAMLBubblesError(t *testing.T) {
	h, _ := newHandler(t)
	_, err := h.BulkImportCustomRules(context.Background(), bulkReq("not: : : valid", "skip"))
	require.Error(t, err)
}

func TestBulkImport_NonWriter_Forbidden(t *testing.T) {
	builtin := fingerprint.Default()
	r := &stubRepo{}
	h, err := New(builtin, r, &stubAuth{p: &auth.UserPrincipal{
		UserID: "u-ta", Username: "ta", TenantID: "t1",
		Role: identitydomain.RoleTenantAuditor,
	}})
	require.NoError(t, err)
	_, err = h.BulkImportCustomRules(context.Background(), bulkReq(validYAML, "skip"))
	require.Error(t, err)
}
