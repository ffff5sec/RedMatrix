package tenancy

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	tenancycrypto "github.com/ffff5sec/RedMatrix/internal/tenancy/crypto"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
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

// === mock registration-token repo ===

type mockTokenRepo struct {
	rows   map[string]*domain.RegistrationToken
	byHash map[string]string
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{
		rows:   map[string]*domain.RegistrationToken{},
		byHash: map[string]string{},
	}
}

func (m *mockTokenRepo) Insert(_ context.Context, t *domain.RegistrationToken) error {
	if err := t.ValidateForCreate(); err != nil {
		return err
	}
	if _, dup := m.byHash[t.TokenHash]; dup {
		return errx.New(errx.ErrNodeRegistrationTokenInvalid, "hash dup")
	}
	if t.ID == "" {
		t.ID = "tk-" + t.Name
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.rows[t.ID] = t
	m.byHash[t.TokenHash] = t.ID
	return nil
}

func (m *mockTokenRepo) GetByHash(_ context.Context, hash string) (*domain.RegistrationToken, error) {
	id, ok := m.byHash[hash]
	if !ok {
		return nil, errx.New(errx.ErrNodeRegistrationTokenInvalid, "not found")
	}
	return m.rows[id], nil
}

func (m *mockTokenRepo) GetByID(_ context.Context, id string) (*domain.RegistrationToken, error) {
	t, ok := m.rows[id]
	if !ok {
		return nil, errx.New(errx.ErrNodeRegistrationTokenInvalid, "not found")
	}
	return t, nil
}

func (m *mockTokenRepo) ListByTenant(_ context.Context, tenantID string) ([]*domain.RegistrationToken, error) {
	var out []*domain.RegistrationToken
	for _, t := range m.rows {
		if t.TenantID == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}

func (m *mockTokenRepo) Revoke(_ context.Context, id string) error {
	t, ok := m.rows[id]
	if !ok {
		return errx.New(errx.ErrNodeRegistrationTokenInvalid, "not found")
	}
	if t.RevokedAt == nil {
		now := time.Now().UTC()
		t.RevokedAt = &now
	}
	return nil
}

func (m *mockTokenRepo) MarkUsed(_ context.Context, id string) error {
	t, ok := m.rows[id]
	if !ok || t.UsedAt != nil || t.RevokedAt != nil {
		return errx.New(errx.ErrNodeRegistrationTokenInvalid, "not usable")
	}
	now := time.Now().UTC()
	t.UsedAt = &now
	return nil
}

// === mock allowed-nodes repo ===

type mockAllowedRepo struct {
	rows map[string]map[string]struct{} // projectID → set(nodeID)
}

func newMockAllowedRepo() *mockAllowedRepo {
	return &mockAllowedRepo{rows: map[string]map[string]struct{}{}}
}

func (m *mockAllowedRepo) Set(_ context.Context, projectID string, nodeIDs []string, _ string) error {
	if len(nodeIDs) == 0 {
		delete(m.rows, projectID)
		return nil
	}
	set := map[string]struct{}{}
	for _, id := range nodeIDs {
		set[id] = struct{}{}
	}
	m.rows[projectID] = set
	return nil
}

func (m *mockAllowedRepo) ClearAll(_ context.Context, projectID string) error {
	delete(m.rows, projectID)
	return nil
}

func (m *mockAllowedRepo) Get(_ context.Context, projectID string) (domain.AllowedNodes, error) {
	set, ok := m.rows[projectID]
	if !ok || len(set) == 0 {
		return domain.AllowedNodes{AllNodes: true}, nil
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	return domain.AllowedNodes{NodeIDs: ids}, nil
}

func (m *mockAllowedRepo) IsAllowed(_ context.Context, projectID, nodeID string) (bool, error) {
	set, ok := m.rows[projectID]
	if !ok || len(set) == 0 {
		return true, nil
	}
	_, in := set[nodeID]
	return in, nil
}

// === mock node repo ===

type mockNodeRepo struct {
	rows        map[string]*domain.Node
	insertCalls int
}

func newMockNodeRepo() *mockNodeRepo {
	return &mockNodeRepo{rows: map[string]*domain.Node{}}
}

func (m *mockNodeRepo) Insert(_ context.Context, n *domain.Node) error {
	m.insertCalls++
	if err := n.ValidateForCreate(); err != nil {
		return err
	}
	for _, ex := range m.rows {
		if ex.TenantID == n.TenantID && ex.Name == n.Name && ex.DeletedAt == nil {
			return errx.New(errx.ErrNodeNameExists, "dup")
		}
	}
	if n.ID == "" {
		n.ID = "n-" + n.Name
	}
	if n.CreatedAt.IsZero() {
		n.CreatedAt = time.Now().UTC()
	}
	m.rows[n.ID] = n
	return nil
}

func (m *mockNodeRepo) GetByID(_ context.Context, id string) (*domain.Node, error) {
	n, ok := m.rows[id]
	if !ok || n.DeletedAt != nil {
		return nil, errx.New(errx.ErrNodeNotFound, "not found")
	}
	return n, nil
}

func (m *mockNodeRepo) List(_ context.Context, f repo.NodeFilter, p repo.Page) ([]*domain.Node, int, error) {
	var matched []*domain.Node
	for _, n := range m.rows {
		if n.DeletedAt != nil {
			continue
		}
		if f.TenantID != "" && n.TenantID != f.TenantID {
			continue
		}
		if f.Status != "" && n.Status != f.Status {
			continue
		}
		matched = append(matched, n)
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

func (m *mockNodeRepo) UpdateStatus(_ context.Context, id string, status domain.NodeStatus) error {
	n, ok := m.rows[id]
	if !ok || n.DeletedAt != nil {
		return errx.New(errx.ErrNodeNotFound, "not found")
	}
	if !status.Valid() {
		return errx.New(errx.ErrInvalidInput, "bad status")
	}
	n.Status = status
	return nil
}

func (m *mockNodeRepo) TouchLastSeen(_ context.Context, id string, ts time.Time) error {
	n, ok := m.rows[id]
	if !ok || n.DeletedAt != nil || n.Status == domain.NodeDisabled {
		return errx.New(errx.ErrNodeNotFound, "not found / disabled")
	}
	t := ts.UTC()
	n.LastSeenAt = &t
	if n.Status == domain.NodePending || n.Status == domain.NodeOffline {
		n.Status = domain.NodeOnline
	}
	return nil
}

func (m *mockNodeRepo) SoftDelete(_ context.Context, id string) error {
	n, ok := m.rows[id]
	if !ok {
		return errx.New(errx.ErrNodeNotFound, "not found")
	}
	if n.DeletedAt == nil {
		now := time.Now().UTC()
		n.DeletedAt = &now
	}
	return nil
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
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, nr, ar, tr, nil, users, nil)
	require.NoError(t, err)
	return svc, r
}

func setupSvcAll(t *testing.T) (Service, *mockProjectRepo, *mockMemberRepo, *mockUserLookup) {
	t.Helper()
	r := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, nr, ar, tr, nil, users, nil)
	require.NoError(t, err)
	return svc, r, mr, users
}

func setupSvcWithNodes(t *testing.T) (Service, *mockNodeRepo) {
	t.Helper()
	r := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, nr, ar, tr, nil, users, nil)
	require.NoError(t, err)
	return svc, nr
}

// setupSvcWithAllowed 给 AllowedNodes 测试用：同时拿到 svc + project repo + node repo + allowed repo。
func setupSvcWithAllowed(t *testing.T) (Service, *mockProjectRepo, *mockNodeRepo, *mockAllowedRepo) {
	t.Helper()
	r := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, nr, ar, tr, nil, users, nil)
	require.NoError(t, err)
	return svc, r, nr, ar
}

// setupSvcWithTokens 给 RegistrationToken 测试用：拿到 svc + node repo + token repo。
func setupSvcWithTokens(t *testing.T) (Service, *mockNodeRepo, *mockTokenRepo) {
	t.Helper()
	r := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	users := newMockUserLookup()
	svc, err := NewService(r, mr, nr, ar, tr, nil, users, nil)
	require.NoError(t, err)
	return svc, nr, tr
}

func TestNewService_NilDeps(t *testing.T) {
	_, err := NewService(nil, nil, nil, nil, nil, nil, nil, nil)
	require.Error(t, err)
	_, err = NewService(newMockProjectRepo(), nil, newMockNodeRepo(),
		newMockAllowedRepo(), newMockTokenRepo(), nil, newMockUserLookup(), nil)
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

// === Node CRUD ===

func TestCreateNode_Happy(t *testing.T) {
	svc, _ := setupSvcWithNodes(t)
	n, err := svc.CreateNode(context.Background(), CreateNodeRequest{
		TenantID:     tenantID,
		Name:         "agent-01",
		Version:      "1.0.0",
		Capabilities: []string{"scan:web"},
		CreatedBy:    "u-sa",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, n.ID)
	assert.Equal(t, domain.NodePending, n.Status)
	assert.Equal(t, "u-sa", n.CreatedBy)
}

func TestCreateNode_EmptyName(t *testing.T) {
	svc, _ := setupSvcWithNodes(t)
	_, err := svc.CreateNode(context.Background(), CreateNodeRequest{
		TenantID: tenantID, Name: " ",
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestCreateNode_DupName(t *testing.T) {
	svc, _ := setupSvcWithNodes(t)
	_, err := svc.CreateNode(context.Background(),
		CreateNodeRequest{TenantID: tenantID, Name: "agent-01"})
	require.NoError(t, err)
	_, err = svc.CreateNode(context.Background(),
		CreateNodeRequest{TenantID: tenantID, Name: "agent-01"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNameExists, c)
}

func TestListNodes_PaginationClamp(t *testing.T) {
	svc, repo := setupSvcWithNodes(t)
	for i := 0; i < 3; i++ {
		require.NoError(t, repo.Insert(context.Background(), &domain.Node{
			TenantID: tenantID,
			Name:     "n-" + string(rune('a'+i)),
			Status:   domain.NodePending,
		}))
	}
	res, err := svc.ListNodes(context.Background(), ListNodesRequest{
		TenantID: tenantID, PageSize: 9999,
	})
	require.NoError(t, err)
	assert.Equal(t, listNodesMaxPageSize, res.PageSize)
	assert.Equal(t, 3, res.Total)
}

func TestEnableDisableDeleteNode(t *testing.T) {
	svc, repo := setupSvcWithNodes(t)
	n, err := svc.CreateNode(context.Background(),
		CreateNodeRequest{TenantID: tenantID, Name: "n-1"})
	require.NoError(t, err)
	originalStatus := n.Status

	require.NoError(t, svc.DisableNode(context.Background(), n.ID))
	got, _ := svc.GetNode(context.Background(), n.ID)
	assert.Equal(t, domain.NodeDisabled, got.Status)

	require.NoError(t, svc.EnableNode(context.Background(), n.ID))
	got, _ = svc.GetNode(context.Background(), n.ID)
	assert.Equal(t, domain.NodePending, got.Status, "Enable 回 pending（等真节点上报）")

	require.NoError(t, svc.DeleteNode(context.Background(), n.ID))
	_, err = svc.GetNode(context.Background(), n.ID)
	require.Error(t, err)
	_ = originalStatus
	_ = repo
}

func TestNodeCRUD_EmptyIDs(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()
	for _, op := range []func() error{
		func() error { _, err := svc.GetNode(ctx, " "); return err },
		func() error { return svc.EnableNode(ctx, " ") },
		func() error { return svc.DisableNode(ctx, " ") },
		func() error { return svc.DeleteNode(ctx, " ") },
	} {
		err := op()
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

// === AllowedNodes ===

// 准备一个项目 + 3 个 node 的 fixture（同 tenant）。
func setupAllowedFixture(t *testing.T) (Service, *mockProjectRepo, *mockNodeRepo, *mockAllowedRepo, string, []string) {
	t.Helper()
	svc, projects, nodes, allowed := setupSvcWithAllowed(t)

	p, err := svc.CreateProject(context.Background(),
		CreateProjectRequest{TenantID: tenantID, Name: "demo"})
	require.NoError(t, err)

	var nodeIDs []string
	for _, name := range []string{"n1", "n2", "n3"} {
		n, err := svc.CreateNode(context.Background(),
			CreateNodeRequest{TenantID: tenantID, Name: name})
		require.NoError(t, err)
		nodeIDs = append(nodeIDs, n.ID)
	}
	return svc, projects, nodes, allowed, p.ID, nodeIDs
}

func TestSetProjectAllowedNodes_Happy(t *testing.T) {
	svc, _, _, _, projectID, nodeIDs := setupAllowedFixture(t)
	ctx := context.Background()

	require.NoError(t, svc.SetProjectAllowedNodes(ctx, SetProjectAllowedNodesRequest{
		ProjectID: projectID,
		NodeIDs:   []string{nodeIDs[0], nodeIDs[1]},
	}))

	got, err := svc.GetProjectAllowedNodes(ctx, projectID)
	require.NoError(t, err)
	assert.False(t, got.AllNodes)
	assert.ElementsMatch(t, []string{nodeIDs[0], nodeIDs[1]}, got.NodeIDs)
}

func TestSetProjectAllowedNodes_Dedup(t *testing.T) {
	svc, _, _, _, projectID, nodeIDs := setupAllowedFixture(t)
	ctx := context.Background()

	require.NoError(t, svc.SetProjectAllowedNodes(ctx, SetProjectAllowedNodesRequest{
		ProjectID: projectID,
		NodeIDs:   []string{nodeIDs[0], nodeIDs[0], nodeIDs[1]},
	}))
	got, err := svc.GetProjectAllowedNodes(ctx, projectID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{nodeIDs[0], nodeIDs[1]}, got.NodeIDs,
		"重复 id 应去重")
}

func TestSetProjectAllowedNodes_EmptyClearAll(t *testing.T) {
	svc, _, _, _, projectID, nodeIDs := setupAllowedFixture(t)
	ctx := context.Background()

	// 先设白名单
	require.NoError(t, svc.SetProjectAllowedNodes(ctx,
		SetProjectAllowedNodesRequest{ProjectID: projectID, NodeIDs: []string{nodeIDs[0]}}))

	// 空 ids → 恢复 ALL
	require.NoError(t, svc.SetProjectAllowedNodes(ctx,
		SetProjectAllowedNodesRequest{ProjectID: projectID, NodeIDs: nil}))

	got, _ := svc.GetProjectAllowedNodes(ctx, projectID)
	assert.True(t, got.AllNodes, "空 ids → 恢复 ALL")
}

func TestSetProjectAllowedNodes_TenantMismatch(t *testing.T) {
	svc, _, _, _, projectID, _ := setupAllowedFixture(t)
	ctx := context.Background()

	// 在另一 tenant 创建一个 node
	otherNode, err := svc.CreateNode(ctx,
		CreateNodeRequest{TenantID: otherTID, Name: "other-1"})
	require.NoError(t, err)

	err = svc.SetProjectAllowedNodes(ctx, SetProjectAllowedNodesRequest{
		ProjectID: projectID,
		NodeIDs:   []string{otherNode.ID},
	})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrAuthzTenantMismatch, c)
}

func TestSetProjectAllowedNodes_NodeNotFound(t *testing.T) {
	svc, _, _, _, projectID, _ := setupAllowedFixture(t)

	err := svc.SetProjectAllowedNodes(context.Background(),
		SetProjectAllowedNodesRequest{
			ProjectID: projectID,
			NodeIDs:   []string{"00000000-0000-0000-0000-000000000aaa"},
		})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNotFound, c)
}

func TestSetProjectAllowedNodes_ProjectNotFound(t *testing.T) {
	svc, _, _, _, _, nodeIDs := setupAllowedFixture(t)

	err := svc.SetProjectAllowedNodes(context.Background(),
		SetProjectAllowedNodesRequest{ProjectID: "p-ghost", NodeIDs: nodeIDs[:1]})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrProjectNotFound, c)
}

func TestGetProjectAllowedNodes_DefaultAllNodes(t *testing.T) {
	svc, _, _, _, projectID, _ := setupAllowedFixture(t)
	got, err := svc.GetProjectAllowedNodes(context.Background(), projectID)
	require.NoError(t, err)
	assert.True(t, got.AllNodes, "新项目默认 ALL")
}

func TestIsNodeAllowedForProject(t *testing.T) {
	svc, _, _, _, projectID, nodeIDs := setupAllowedFixture(t)
	ctx := context.Background()

	// 默认（无白名单）→ 允许
	ok, err := svc.IsNodeAllowedForProject(ctx, projectID, nodeIDs[0])
	require.NoError(t, err)
	assert.True(t, ok)

	// 设白名单 → 仅其中允许
	require.NoError(t, svc.SetProjectAllowedNodes(ctx, SetProjectAllowedNodesRequest{
		ProjectID: projectID,
		NodeIDs:   []string{nodeIDs[1]},
	}))
	ok, _ = svc.IsNodeAllowedForProject(ctx, projectID, nodeIDs[0])
	assert.False(t, ok)
	ok, _ = svc.IsNodeAllowedForProject(ctx, projectID, nodeIDs[1])
	assert.True(t, ok)
}

func TestAllowedNodes_EmptyIDs(t *testing.T) {
	svc, _ := setupSvc(t)
	ctx := context.Background()
	for _, op := range []func() error{
		func() error { return svc.SetProjectAllowedNodes(ctx, SetProjectAllowedNodesRequest{}) },
		func() error { _, err := svc.GetProjectAllowedNodes(ctx, " "); return err },
		func() error { _, err := svc.IsNodeAllowedForProject(ctx, " ", "n"); return err },
		func() error { _, err := svc.IsNodeAllowedForProject(ctx, "p", " "); return err },
	} {
		err := op()
		require.Error(t, err)
		c, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, c)
	}
}

// === RegistrationToken ===

func TestCreateRegistrationToken_Happy(t *testing.T) {
	svc, _, tr := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(), CreateRegistrationTokenRequest{
		TenantID:  tenantID,
		Name:      "batch-1",
		CreatedBy: "u-sa",
	})
	require.NoError(t, err)
	require.NotNil(t, res.Token)
	assert.NotEmpty(t, res.Token.ID)
	assert.NotEmpty(t, res.Plaintext)
	assert.True(t, len(res.Plaintext) > 40, "plaintext 含 prefix + 32 字节 base64url")
	assert.Equal(t, "batch-1", res.Token.Name)
	assert.Nil(t, res.Token.UsedAt)
	assert.Nil(t, res.Token.RevokedAt)
	// hash 入库；plaintext 不入库
	assert.Equal(t, 1, len(tr.byHash))
}

func TestCreateRegistrationToken_TTLClamp(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	cases := []struct {
		name    string
		ttl     time.Duration
		wantErr bool
	}{
		{"zero default", 0, false},
		{"min 1m", time.Minute, false},
		{"max 24h", 24 * time.Hour, false},
		{"too short", 30 * time.Second, true},
		{"too long", 25 * time.Hour, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateRegistrationToken(context.Background(),
				CreateRegistrationTokenRequest{
					TenantID: tenantID, Name: "t-" + tc.name, TTL: tc.ttl,
				})
			if tc.wantErr {
				require.Error(t, err)
				c, _ := errx.GetCode(err)
				assert.Equal(t, errx.ErrInvalidInput, c)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreateRegistrationToken_EmptyInputs(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	cases := []CreateRegistrationTokenRequest{
		{Name: "x"},                      // tenant 空
		{TenantID: tenantID, Name: "  "}, // name 空
	}
	for _, c := range cases {
		_, err := svc.CreateRegistrationToken(context.Background(), c)
		require.Error(t, err)
		code, _ := errx.GetCode(err)
		assert.Equal(t, errx.ErrInvalidInput, code)
	}
}

func TestRevokeRegistrationToken(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "rev"})
	require.NoError(t, err)

	require.NoError(t, svc.RevokeRegistrationToken(context.Background(), res.Token.ID))
	// 再撤一次仍幂等
	require.NoError(t, svc.RevokeRegistrationToken(context.Background(), res.Token.ID))
}

func TestListRegistrationTokens(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	for i := 0; i < 3; i++ {
		_, err := svc.CreateRegistrationToken(context.Background(),
			CreateRegistrationTokenRequest{
				TenantID: tenantID,
				Name:     "t-" + string(rune('a'+i)),
			})
		require.NoError(t, err)
	}
	got, err := svc.ListRegistrationTokens(context.Background(), tenantID)
	require.NoError(t, err)
	assert.Len(t, got, 3)
}

// === RedeemRegistrationToken ===

func TestRedeemRegistrationToken_Happy(t *testing.T) {
	svc, nr, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "redeem"})
	require.NoError(t, err)

	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{
			Plaintext: res.Plaintext,
			NodeName:  "agent-01",
			Version:   "1.0.0",
		})
	require.NoError(t, err)
	require.NotNil(t, rd.Node)
	assert.Equal(t, "agent-01", rd.Node.Name)
	assert.Equal(t, domain.NodePending, rd.Node.Status)
	assert.Equal(t, tenantID, rd.Node.TenantID)
	assert.Equal(t, "1.0.0", rd.Node.Version)

	// node 已落 mock
	assert.Len(t, nr.rows, 1)
}

func TestRedeemRegistrationToken_BadFormat(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	_, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: "not-a-token", NodeName: "x"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRedeemRegistrationToken_EmptyName(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "x"})
	require.NoError(t, err)
	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: " "})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

func TestRedeemRegistrationToken_NotFound(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	// 自己生成一个真实格式但未入库的 plaintext
	gen, err := tenancycrypto.GenerateNodeToken()
	require.NoError(t, err)
	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: gen.Plaintext, NodeName: "x"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRedeemRegistrationToken_AlreadyUsed_DoubleSpendBlocked(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "once"})
	require.NoError(t, err)

	// 第一次 OK
	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: "agent-1"})
	require.NoError(t, err)

	// 第二次必须失败（防双花）
	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: "agent-2"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

// === Heartbeat（PR-T4-D3）===

func TestHeartbeat_Happy_PendingToOnline(t *testing.T) {
	svc, nr, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "hb"})
	require.NoError(t, err)
	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: "agent-hb"})
	require.NoError(t, err)
	require.Equal(t, domain.NodePending, nr.rows[rd.Node.ID].Status)

	hb, err := svc.Heartbeat(context.Background(), HeartbeatRequest{NodeID: rd.Node.ID})
	require.NoError(t, err)
	assert.Equal(t, domain.HeartbeatInterval, hb.Interval)
	assert.False(t, hb.ServerTime.IsZero())

	persisted := nr.rows[rd.Node.ID]
	assert.Equal(t, domain.NodeOnline, persisted.Status, "首次 heartbeat 应推 pending→online")
	assert.NotNil(t, persisted.LastSeenAt)
}

func TestHeartbeat_OfflineToOnline(t *testing.T) {
	svc, nr, _ := setupSvcWithTokens(t)
	// 直接造一个 offline 节点
	long := time.Now().Add(-10 * time.Minute)
	n := &domain.Node{
		TenantID: tenantID, Name: "offliner", Status: domain.NodeOffline,
		LastSeenAt: &long,
	}
	require.NoError(t, nr.Insert(context.Background(), n))

	_, err := svc.Heartbeat(context.Background(), HeartbeatRequest{NodeID: n.ID})
	require.NoError(t, err)
	assert.Equal(t, domain.NodeOnline, nr.rows[n.ID].Status)
}

func TestHeartbeat_DisabledRejected(t *testing.T) {
	svc, nr, _ := setupSvcWithTokens(t)
	n := &domain.Node{
		TenantID: tenantID, Name: "disabled", Status: domain.NodeDisabled,
	}
	require.NoError(t, nr.Insert(context.Background(), n))

	_, err := svc.Heartbeat(context.Background(), HeartbeatRequest{NodeID: n.ID})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNotFound, c, "disabled 节点不能被 heartbeat 复活")
	assert.Equal(t, domain.NodeDisabled, nr.rows[n.ID].Status)
}

func TestHeartbeat_NotFound(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	_, err := svc.Heartbeat(context.Background(),
		HeartbeatRequest{NodeID: "00000000-0000-0000-0000-000000000999"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeNotFound, c)
}

func TestHeartbeat_EmptyNodeID(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	_, err := svc.Heartbeat(context.Background(), HeartbeatRequest{})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, c)
}

// === RedeemRegistrationToken + 签 cert（PR-T4-D2）===

type mockCertRepo struct {
	rows      map[string]*domain.NodeCertificate
	insertErr error
}

func newMockCertRepo() *mockCertRepo {
	return &mockCertRepo{rows: map[string]*domain.NodeCertificate{}}
}

func (m *mockCertRepo) Insert(_ context.Context, c *domain.NodeCertificate) error {
	if m.insertErr != nil {
		return m.insertErr
	}
	if err := c.ValidateForCreate(); err != nil {
		return err
	}
	c.ID = "00000000-0000-0000-0000-" + padID(len(m.rows)+1)
	m.rows[c.ID] = c
	return nil
}

func padID(n int) string {
	s := "000000000000"
	for i := 0; n > 0 && i < len(s); i++ {
		s = s[:len(s)-1-i] + string(rune('0'+(n%10))) + s[len(s)-i:]
		n /= 10
	}
	return s
}

func (m *mockCertRepo) GetBySerial(_ context.Context, serial string) (*domain.NodeCertificate, error) {
	for _, c := range m.rows {
		if c.SerialNumber == serial {
			return c, nil
		}
	}
	return nil, errx.New(errx.ErrNodeCertExpired, "not found")
}

func (m *mockCertRepo) GetByFingerprint(_ context.Context, fp string) (*domain.NodeCertificate, error) {
	for _, c := range m.rows {
		if c.Fingerprint == fp {
			return c, nil
		}
	}
	return nil, errx.New(errx.ErrNodeCertExpired, "not found")
}

func (m *mockCertRepo) ListByNode(_ context.Context, nodeID string) ([]*domain.NodeCertificate, error) {
	out := []*domain.NodeCertificate{}
	for _, c := range m.rows {
		if c.NodeID == nodeID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockCertRepo) Revoke(_ context.Context, id string) error {
	c, ok := m.rows[id]
	if !ok {
		return errx.New(errx.ErrNodeCertExpired, "not found")
	}
	if c.RevokedAt == nil {
		now := time.Now().UTC()
		c.RevokedAt = &now
	}
	return nil
}

// setupSvcWithCA 给 D2 测试用：装一个真 CA + mockCertRepo + 全 mock，返 svc + 三件套。
func setupSvcWithCA(t *testing.T) (Service, *mockTokenRepo, *mockCertRepo) {
	t.Helper()
	ca, err := pki.GenerateCA(pki.GenerateCAOptions{})
	require.NoError(t, err)
	pr := newMockProjectRepo()
	mr := newMockMemberRepo()
	nr := newMockNodeRepo()
	ar := newMockAllowedRepo()
	tr := newMockTokenRepo()
	cr := newMockCertRepo()
	users := newMockUserLookup()
	svc, err := NewService(pr, mr, nr, ar, tr, cr, users, ca)
	require.NoError(t, err)
	return svc, tr, cr
}

func TestRedeemRegistrationToken_IssuesCert(t *testing.T) {
	svc, _, cr := setupSvcWithCA(t)
	gen, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "with-ca"})
	require.NoError(t, err)

	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{
			Plaintext: gen.Plaintext,
			NodeName:  "agent-secure",
			Version:   "1.0.0",
		})
	require.NoError(t, err)
	require.NotNil(t, rd.Node)

	// cert 字段全填
	assert.NotEmpty(t, rd.NodeCertPEM, "node cert PEM 应被签发")
	assert.NotEmpty(t, rd.NodeKeyPEM, "node key PEM 应返还")
	assert.NotEmpty(t, rd.CACertPEM, "CA cert PEM 应返还")
	assert.Len(t, rd.Fingerprint, 64, "fingerprint 必须是 SHA-256 hex")
	assert.True(t, rd.CertExpiresAt.After(time.Now()), "cert 必须未过期")

	// repo 已落
	assert.Len(t, cr.rows, 1)
	for _, c := range cr.rows {
		assert.Equal(t, rd.Node.ID, c.NodeID)
		assert.Equal(t, rd.Fingerprint, c.Fingerprint)
		assert.Equal(t, rd.Node.ID, c.CommonName)
	}
}

func TestRedeemRegistrationToken_NoCA_SkipsCertIssuance(t *testing.T) {
	// 没注 CA → 旧路径：仅返 Node，cert 字段全空
	svc, _, _ := setupSvcWithTokens(t)
	gen, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "no-ca"})
	require.NoError(t, err)

	rd, err := svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{
			Plaintext: gen.Plaintext,
			NodeName:  "agent-plain",
		})
	require.NoError(t, err)
	assert.Empty(t, rd.NodeCertPEM)
	assert.Empty(t, rd.NodeKeyPEM)
	assert.Empty(t, rd.CACertPEM)
	assert.Empty(t, rd.Fingerprint)
}

func TestRedeemRegistrationToken_Revoked(t *testing.T) {
	svc, _, _ := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "rev"})
	require.NoError(t, err)
	require.NoError(t, svc.RevokeRegistrationToken(context.Background(), res.Token.ID))

	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: "x"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}

func TestRedeemRegistrationToken_Expired(t *testing.T) {
	svc, _, tr := setupSvcWithTokens(t)
	res, err := svc.CreateRegistrationToken(context.Background(),
		CreateRegistrationTokenRequest{TenantID: tenantID, Name: "exp"})
	require.NoError(t, err)
	// 手动改 ExpiresAt 到过去（mockTokenRepo 持的是同一指针）
	tr.rows[res.Token.ID].ExpiresAt = time.Now().Add(-time.Minute)

	_, err = svc.RedeemRegistrationToken(context.Background(),
		RedeemRegistrationTokenRequest{Plaintext: res.Plaintext, NodeName: "x"})
	require.Error(t, err)
	c, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrNodeRegistrationTokenInvalid, c)
}
