package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// === mock member repo + user lookup ===

type mockMemberRepo struct {
	rows         map[string]*domain.ProjectMember // key = projectID + ":" + userID
	addErr       error
	addCalls     int
	removeCalls  int
	listCalls    int
	listIDsCalls int
}

func newMockMemberRepo() *mockMemberRepo {
	return &mockMemberRepo{rows: map[string]*domain.ProjectMember{}}
}

func memberKey(projectID, userID string) string {
	return projectID + ":" + userID
}

func (m *mockMemberRepo) Add(_ context.Context, mem *domain.ProjectMember) error {
	m.addCalls++
	if m.addErr != nil {
		return m.addErr
	}
	if err := mem.ValidateForCreate(); err != nil {
		return err
	}
	k := memberKey(mem.ProjectID, mem.UserID)
	if _, exists := m.rows[k]; exists {
		return errx.New(errx.ErrProjectMemberExists, "dup")
	}
	if mem.AddedAt.IsZero() {
		mem.AddedAt = time.Now().UTC()
	}
	m.rows[k] = mem
	return nil
}

func (m *mockMemberRepo) Remove(_ context.Context, projectID, userID string) error {
	m.removeCalls++
	k := memberKey(projectID, userID)
	if _, ok := m.rows[k]; !ok {
		return errx.New(errx.ErrProjectMemberNotFound, "nf")
	}
	delete(m.rows, k)
	return nil
}

func (m *mockMemberRepo) Exists(_ context.Context, projectID, userID string) (bool, error) {
	_, ok := m.rows[memberKey(projectID, userID)]
	return ok, nil
}

func (m *mockMemberRepo) ListByProject(_ context.Context, projectID string) ([]*domain.ProjectMember, error) {
	m.listCalls++
	var out []*domain.ProjectMember
	for _, mem := range m.rows {
		if mem.ProjectID == projectID {
			out = append(out, mem)
		}
	}
	return out, nil
}

func (m *mockMemberRepo) ListProjectIDsByUser(_ context.Context, userID string) ([]string, error) {
	m.listIDsCalls++
	var out []string
	for _, mem := range m.rows {
		if mem.UserID == userID {
			out = append(out, mem.ProjectID)
		}
	}
	return out, nil
}

// mockUserLookup 实现 UserLookup（service AddProjectMember 用）。
type mockUserLookup struct {
	users map[string]*identitydomain.User
	err   error
}

func newMockUserLookup() *mockUserLookup {
	return &mockUserLookup{users: map[string]*identitydomain.User{}}
}

func (m *mockUserLookup) put(u *identitydomain.User) { m.users[u.ID] = u }

func (m *mockUserLookup) GetByID(_ context.Context, id string) (*identitydomain.User, error) {
	if m.err != nil {
		return nil, m.err
	}
	u, ok := m.users[id]
	if !ok {
		return nil, errx.New(errx.ErrUserNotFound, "nf")
	}
	return u, nil
}

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
	mr := newMockMemberRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, users)
	require.NoError(t, err)
	return svc, r
}

func setupSvcAll(t *testing.T) (Service, *mockProjectRepo, *mockMemberRepo, *mockUserLookup) {
	t.Helper()
	r := newMockProjectRepo()
	mr := newMockMemberRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, users)
	require.NoError(t, err)
	return svc, r, mr, users
}

func TestNewService_NilDeps(t *testing.T) {
	_, err := NewService(nil, nil, nil)
	require.Error(t, err)
	_, err = NewService(newMockProjectRepo(), nil, newMockUserLookup())
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
		func() error { return svc.RemoveProjectMember(ctx, " ", "u-1") },
		func() error { return svc.RemoveProjectMember(ctx, "p-1", " ") },
		func() error { _, err := svc.ListProjectMembers(ctx, " "); return err },
	} {
		err := op()
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

// === ProjectMember CRUD ===

const (
	tenantID = DefaultAccountID
	otherTID = "00000000-0000-0000-0000-0000000000ff"
	paUserID = "u-pa"
	saUserID = "u-sa"
	taUserID = "u-ta"
)

func paUser(id, tID string) *identitydomain.User {
	return &identitydomain.User{
		ID: id, TenantID: tID, Username: id,
		Role: identitydomain.RoleProjectAdmin, Status: identitydomain.StatusActive,
	}
}

func TestAddProjectMember_Happy(t *testing.T) {
	svc, _, members, users := setupSvcAll(t)
	users.put(paUser(paUserID, tenantID))
	p, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})
	require.NoError(t, err)

	require.NoError(t, svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p.ID, UserID: paUserID, AddedBy: saUserID}))
	exists, _ := members.Exists(context.Background(), p.ID, paUserID)
	assert.True(t, exists)
}

func TestAddProjectMember_RejectsNonPA(t *testing.T) {
	svc, _, _, users := setupSvcAll(t)
	users.put(&identitydomain.User{
		ID: taUserID, TenantID: tenantID, Username: "ta",
		Role: identitydomain.RoleTenantAuditor, Status: identitydomain.StatusActive,
	})
	p, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})

	err := svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p.ID, UserID: taUserID})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectMemberRoleInvalid, c)
}

func TestAddProjectMember_RejectsCrossTenant(t *testing.T) {
	svc, _, _, users := setupSvcAll(t)
	users.put(paUser(paUserID, otherTID)) // 用户在另一租户
	p, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})

	err := svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p.ID, UserID: paUserID})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthzTenantMismatch, c)
}

func TestAddProjectMember_ProjectNotFound(t *testing.T) {
	svc, _, _, users := setupSvcAll(t)
	users.put(paUser(paUserID, tenantID))
	err := svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: "p-ghost", UserID: paUserID})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

func TestAddProjectMember_UserNotFound(t *testing.T) {
	svc, _, _, _ := setupSvcAll(t)
	p, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})

	err := svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p.ID, UserID: "u-ghost"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrUserNotFound, c)
}

func TestRemoveProjectMember_Happy(t *testing.T) {
	svc, _, members, users := setupSvcAll(t)
	users.put(paUser(paUserID, tenantID))
	p, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})
	require.NoError(t, svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p.ID, UserID: paUserID}))

	require.NoError(t, svc.RemoveProjectMember(context.Background(), p.ID, paUserID))
	exists, _ := members.Exists(context.Background(), p.ID, paUserID)
	assert.False(t, exists)
}

func TestListProjectMembers_RequiresProjectExists(t *testing.T) {
	svc, _ := setupSvc(t)
	_, err := svc.ListProjectMembers(context.Background(), "p-ghost")
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

// === ListProjects PA filter ===

func TestListProjects_PAOnlySeesJoined(t *testing.T) {
	svc, _, _, users := setupSvcAll(t)
	users.put(paUser(paUserID, tenantID))

	// SA 创建 3 项目
	p1, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "alpha"})
	p2, _ := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "bravo"})
	_, _ = svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "charlie"})

	// PA 加入 alpha + bravo
	require.NoError(t, svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p1.ID, UserID: paUserID}))
	require.NoError(t, svc.AddProjectMember(context.Background(),
		AddProjectMemberRequest{ProjectID: p2.ID, UserID: paUserID}))

	// PA 视角：仅看到 2
	res, err := svc.ListProjects(context.Background(), ListProjectsRequest{
		TenantID:     tenantID,
		MemberUserID: paUserID,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res.Total)
	require.Len(t, res.Projects, 2)
	names := []string{res.Projects[0].Name, res.Projects[1].Name}
	assert.ElementsMatch(t, []string{"alpha", "bravo"}, names)

	// SA 视角（无 MemberUserID）：3 个全见
	res, err = svc.ListProjects(context.Background(), ListProjectsRequest{TenantID: tenantID})
	require.NoError(t, err)
	assert.Equal(t, 3, res.Total)
}

func TestListProjects_PAWithNoJoined_ReturnsEmpty(t *testing.T) {
	svc, _, _, _ := setupSvcAll(t)
	_, _ = svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "alpha"})

	res, err := svc.ListProjects(context.Background(), ListProjectsRequest{
		TenantID:     tenantID,
		MemberUserID: paUserID, // 没加入任何项目
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res.Total)
	assert.Empty(t, res.Projects)
}
