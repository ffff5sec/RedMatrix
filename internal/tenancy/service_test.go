package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// === mock project repo ===

type mockProjectRepo struct {
	rows         map[string]*domain.Project
	insertErr    error
	insertCalls  int
	archiveErr   error
	archiveCalls int
	deletedIDs   map[string]bool
}

func newMockProjectRepo() *mockProjectRepo {
	return &mockProjectRepo{
		rows:       map[string]*domain.Project{},
		deletedIDs: map[string]bool{},
	}
}

func (m *mockProjectRepo) Insert(_ context.Context, p *domain.Project) error {
	m.insertCalls++
	if m.insertErr != nil {
		return m.insertErr
	}
	if err := p.ValidateForCreate(); err != nil {
		return err
	}
	// dup name in tenant
	for _, ex := range m.rows {
		if ex.TenantID == p.TenantID && ex.Name == p.Name && ex.DeletedAt == nil {
			return errx.New(errx.ErrProjectNameExists, "dup")
		}
	}
	if p.ID == "" {
		p.ID = "p-" + p.Name
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	m.rows[p.ID] = p
	return nil
}

func (m *mockProjectRepo) GetByID(_ context.Context, id string) (*domain.Project, error) {
	p, ok := m.rows[id]
	if !ok || (p.DeletedAt != nil) {
		return nil, errx.New(errx.ErrProjectNotFound, "not found")
	}
	return p, nil
}

func (m *mockProjectRepo) List(_ context.Context, f repo.ProjectFilter, p repo.Page) ([]*domain.Project, int, error) {
	var matched []*domain.Project
	for _, pr := range m.rows {
		if pr.DeletedAt != nil {
			continue
		}
		if f.TenantID != "" && pr.TenantID != f.TenantID {
			continue
		}
		if f.Status != "" && pr.Status != f.Status {
			continue
		}
		matched = append(matched, pr)
	}
	if p.PageSize <= 0 {
		p.PageSize = 20
	}
	if p.Page < 1 {
		p.Page = 1
	}
	total := len(matched)
	start := (p.Page - 1) * p.PageSize
	end := start + p.PageSize
	if start > total {
		return nil, total, nil
	}
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

func (m *mockProjectRepo) Archive(_ context.Context, id string) error {
	m.archiveCalls++
	if m.archiveErr != nil {
		return m.archiveErr
	}
	p, ok := m.rows[id]
	if !ok || p.DeletedAt != nil {
		return errx.New(errx.ErrProjectNotFound, "not found")
	}
	p.Status = domain.ProjectArchived
	if p.ArchivedAt == nil {
		now := time.Now().UTC()
		p.ArchivedAt = &now
	}
	return nil
}

func (m *mockProjectRepo) Unarchive(_ context.Context, id string) error {
	p, ok := m.rows[id]
	if !ok || p.DeletedAt != nil {
		return errx.New(errx.ErrProjectNotFound, "not found")
	}
	p.Status = domain.ProjectActive
	p.ArchivedAt = nil
	return nil
}

func (m *mockProjectRepo) SoftDelete(_ context.Context, id string) error {
	p, ok := m.rows[id]
	if !ok {
		return errx.New(errx.ErrProjectNotFound, "not found")
	}
	if p.DeletedAt == nil {
		now := time.Now().UTC()
		p.DeletedAt = &now
	}
	return nil
}

// === Tests ===

func setupSvc(t *testing.T) (Service, *mockProjectRepo) {
	t.Helper()
	r := newMockProjectRepo()
	svc, err := NewService(r)
	require.NoError(t, err)
	return svc, r
}

func TestNewService_NilRepo(t *testing.T) {
	_, err := NewService(nil)
	require.Error(t, err)
}

func TestCreateProject_Happy(t *testing.T) {
	svc, _ := setupSvc(t)
	p, err := svc.CreateProject(context.Background(), CreateProjectRequest{
		TenantID:  DefaultAccountID,
		Name:      "demo",
		CreatedBy: "u-sa",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, p.ID)
	assert.Equal(t, "demo", p.Name)
	assert.Equal(t, domain.ProjectActive, p.Status)
	assert.Equal(t, "u-sa", p.CreatedBy)
}

func TestCreateProject_EmptyTenant(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.CreateProject(context.Background(), CreateProjectRequest{Name: "x"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestCreateProject_EmptyName(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: DefaultAccountID, Name: " "})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestCreateProject_DuplicateName(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: DefaultAccountID, Name: "demo"})
	require.NoError(t, err)
	_, err = svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: DefaultAccountID, Name: "demo"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNameExists, c)
}

func TestListProjects_PaginationClamp(t *testing.T) {
	svc, r := setupSvc(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, r.Insert(context.Background(), &domain.Project{
			TenantID: DefaultAccountID,
			Name:     "p-" + string(rune('a'+i)),
			Status:   domain.ProjectActive,
		}))
	}
	res, err := svc.ListProjects(context.Background(), ListProjectsRequest{
		TenantID: DefaultAccountID, PageSize: 9999,
	})
	require.NoError(t, err)
	assert.Equal(t, listProjectsMaxPageSize, res.PageSize, "PageSize 应被钳到上限")
	assert.Equal(t, 3, res.Total)
	assert.Len(t, res.Projects, 3)
}

func TestGetProject_NotFound(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.GetProject(context.Background(), "ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

func TestArchiveUnarchive(t *testing.T) {
	svc, r := setupSvc(t)
	p, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: DefaultAccountID, Name: "demo"})
	require.NoError(t, err)

	require.NoError(t, svc.ArchiveProject(context.Background(), p.ID))
	got, err := svc.GetProject(context.Background(), p.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ProjectArchived, got.Status)

	require.NoError(t, svc.UnarchiveProject(context.Background(), p.ID))
	got, err = svc.GetProject(context.Background(), p.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ProjectActive, got.Status)
	_ = r // suppress unused
}

func TestDeleteProject(t *testing.T) {
	svc, _ := setupSvc(t)
	p, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: DefaultAccountID, Name: "demo"})
	require.NoError(t, err)

	require.NoError(t, svc.DeleteProject(context.Background(), p.ID))
	_, err = svc.GetProject(context.Background(), p.ID)
	require.Error(t, err, "已删项目应返 NotFound")
}

func TestEmptyIDs(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()
	for _, op := range []func() error{
		func() error { _, err := svc.GetProject(ctx, " "); return err },
		func() error { return svc.ArchiveProject(ctx, " ") },
		func() error { return svc.UnarchiveProject(ctx, " ") },
		func() error { return svc.DeleteProject(ctx, " ") },
	} {
		err := op()
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}
