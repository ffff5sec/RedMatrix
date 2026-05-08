package tenancy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	identitydomain "github.com/ffff5sec/RedMatrix/internal/identity/domain"
	tenancycrypto "github.com/ffff5sec/RedMatrix/internal/tenancy/crypto"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/domain"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/pki"
	"github.com/ffff5sec/RedMatrix/internal/tenancy/repo"
)

// UserLookup 是 service 用来校"被加成员是否合法用户 + 角色 + tenant"的接口。
//
// 故意不直接 import identity/repo.Repository（避免互依赖体积放大）；只取这一个
// 方法。idiomatic 用法：传入 identityrepo.NewPG(...) 自动满足。
type UserLookup interface {
	GetByID(ctx context.Context, id string) (*identitydomain.User, error)
}

// Service 是 tenancy 模块的业务流接口。
//
// PR-T2/T3 范围：Project CRUD + ProjectMember CRUD。
// Authz（角色检查）由 handler 层做；service 不查 caller role。
type Service interface {
	// CreateProject 在租户内创建项目。name 在租户内唯一（活项目）。
	CreateProject(ctx context.Context, req CreateProjectRequest) (*domain.Project, error)

	// ListProjects 列租户内项目；分页 + 过滤。
	// req.MemberUserID 非空 → 仅列该用户加入的项目（PA 视角；handler 注入）。
	ListProjects(ctx context.Context, req ListProjectsRequest) (*ListProjectsResult, error)

	// GetProject 取单个项目（已软删返 NotFound）。
	GetProject(ctx context.Context, id string) (*domain.Project, error)

	// ArchiveProject 归档。幂等。
	ArchiveProject(ctx context.Context, id string) error

	// UnarchiveProject 取消归档。幂等。
	UnarchiveProject(ctx context.Context, id string) error

	// DeleteProject 软删（暂不级联 cascade，留给后续 PR）。
	// 删除后 GetByID/List 都不再可见。
	DeleteProject(ctx context.Context, id string) error

	// AddProjectMember 加成员。
	// service 校：被加用户必须存在 + role==ProjectAdmin + tenant 与项目一致；
	// 重复加 → ErrProjectMemberExists（幂等性留给 caller 决定）。
	AddProjectMember(ctx context.Context, req AddProjectMemberRequest) error

	// RemoveProjectMember 移除成员。
	RemoveProjectMember(ctx context.Context, projectID, userID string) error

	// ListProjectMembers 列项目成员（按 added_at ASC）。
	ListProjectMembers(ctx context.Context, projectID string) ([]*domain.ProjectMember, error)

	// CreateNode 在租户内手动注册节点（MVP；完整 RegistrationToken 流程见 PR-T4-B）。
	CreateNode(ctx context.Context, req CreateNodeRequest) (*domain.Node, error)

	// ListNodes 列租户内节点；分页 + 过滤。
	ListNodes(ctx context.Context, req ListNodesRequest) (*ListNodesResult, error)

	// GetNode 取单个节点。
	GetNode(ctx context.Context, id string) (*domain.Node, error)

	// EnableNode 状态置 pending（重置回未连接，等待真节点上线）。MVP 演示用。
	EnableNode(ctx context.Context, id string) error

	// DisableNode 状态置 disabled。该节点不再被任务调度。
	DisableNode(ctx context.Context, id string) error

	// DeleteNode 软删（MVP 不级联 task / 白名单清理）。
	DeleteNode(ctx context.Context, id string) error

	// SetProjectAllowedNodes 设置项目可用节点白名单（全量替换）。
	// 校：项目存在 + 每个 node 同 tenant 且未软删。空 ids → ClearAll（恢复 ALL）。
	SetProjectAllowedNodes(ctx context.Context, req SetProjectAllowedNodesRequest) error

	// GetProjectAllowedNodes 取项目当前白名单（无任何条目 → AllNodes=true）。
	GetProjectAllowedNodes(ctx context.Context, projectID string) (domain.AllowedNodes, error)

	// IsNodeAllowedForProject Scan 调用：项目 + 节点 → 是否允许。
	IsNodeAllowedForProject(ctx context.Context, projectID, nodeID string) (bool, error)

	// CreateRegistrationToken 生成一次性节点注册令牌（SA only）。
	// 返 plaintext 仅一次性显示；hash 入库。
	CreateRegistrationToken(ctx context.Context, req CreateRegistrationTokenRequest) (*CreateRegistrationTokenResult, error)

	// ListRegistrationTokens 列租户全部令牌（SA / TA）。
	ListRegistrationTokens(ctx context.Context, tenantID string) ([]*domain.RegistrationToken, error)

	// RevokeRegistrationToken 撤销令牌（SA only）。
	RevokeRegistrationToken(ctx context.Context, id string) error

	// RedeemRegistrationToken（公开 RPC；bearer token 自身即认证）：
	// 用 plaintext 兑换 → 创建 Node 行（status=pending）+ 标 used。
	// 错码：hash 找不到 / 已用 / 已撤 / 已过期 → ErrNodeRegistrationTokenInvalid
	RedeemRegistrationToken(ctx context.Context, req RedeemRegistrationTokenRequest) (*RedeemRegistrationTokenResult, error)

	// Heartbeat（mTLS RPC；caller 身份由中间件按指纹反查注 ctx）：
	// 写 last_seen_at，pending/offline → online；错码：node 不存在或 disabled
	// → ErrNodeNotFound（让 Agent 退出循环）。
	Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResult, error)
}

// CreateProjectRequest 入参。
type CreateProjectRequest struct {
	TenantID    string // 由 handler 从 principal.TenantID 注（SuperAdmin 跨租户时由 caller 显式指定）
	Name        string
	Description string
	Settings    map[string]any
	CreatedBy   string // user id；handler 从 principal 注
}

// ListProjectsRequest 入参。
type ListProjectsRequest struct {
	TenantID string               // 空 = 跨租户（SA / TA 用）
	Status   domain.ProjectStatus // 空 = 不过滤
	Keyword  string
	Page     int
	PageSize int

	// MemberUserID 非空 → 仅返回该用户加入的项目（PA 视角；handler 注入
	// principal.UserID）。SA / TA 路径留空。
	MemberUserID string
}

// AddProjectMemberRequest 入参。
type AddProjectMemberRequest struct {
	ProjectID string
	UserID    string
	AddedBy   string // caller user id
}

// CreateNodeRequest 入参。
type CreateNodeRequest struct {
	TenantID     string
	Name         string
	Version      string
	Capabilities []string
	CreatedBy    string
}

// ListNodesRequest 入参。
type ListNodesRequest struct {
	TenantID string
	Status   domain.NodeStatus
	Keyword  string
	Page     int
	PageSize int
}

// ListNodesResult 返回。
type ListNodesResult struct {
	Nodes    []*domain.Node
	Total    int
	Page     int
	PageSize int
}

// SetProjectAllowedNodesRequest 入参。
//
// NodeIDs 空切片有特殊语义：清空白名单 → 项目恢复 ALL 默认（所有节点可用）。
// 这与 "禁用所有节点" 不同（schema 不区分；service 选 ALL 语义对 demo 更友好）。
type SetProjectAllowedNodesRequest struct {
	ProjectID string
	NodeIDs   []string
	AddedBy   string
}

// CreateRegistrationTokenRequest 入参。
type CreateRegistrationTokenRequest struct {
	TenantID  string
	Name      string
	TTL       time.Duration // 0 → 默认 1h；上限 24h；下限 1m
	CreatedBy string
}

// CreateRegistrationTokenResult 返回。
//
// Plaintext 一次性返给 SA；下次拉同一 token 仅能见 hash（不可读）。
type CreateRegistrationTokenResult struct {
	Token     *domain.RegistrationToken
	Plaintext string
}

// HeartbeatRequest 入参；node_id 由中间件按指纹注 ctx，不在请求里。
type HeartbeatRequest struct {
	NodeID  string // mTLS 中间件从 cert fingerprint 反查注入；handler 不直接信任 client
	Version string // Agent 上报版本（可选；非空时回写 nodes.version）
}

// HeartbeatResult 返回；ServerTime 让 Agent 同步系统时钟漂移，Interval 是
// 下一次心跳期望延迟（30s）。Agent 实现可按 jitter 浮动 ±10%。
type HeartbeatResult struct {
	ServerTime time.Time
	Interval   time.Duration
}

// RedeemRegistrationTokenRequest 入参。
type RedeemRegistrationTokenRequest struct {
	Plaintext string // 完整 rmnode_xxx 字串
	NodeName  string // Agent 自报名（租户内唯一）
	Version   string // Agent 版本（可空）
}

// RedeemRegistrationTokenResult 返回。
//
// PR-T4-D2 起：若 service 注入了 CA，Redeem 时一并签发节点 cert：
//   - NodeCertPEM / NodeKeyPEM 一次性返给 Agent（key 不入库）
//   - CACertPEM 让 Agent 校验 server cert
//   - Fingerprint = SHA-256(DER) hex（节点身份；mTLS 校验用）
type RedeemRegistrationTokenResult struct {
	Node          *domain.Node
	NodeCertPEM   string // 空：service 未注入 CA（与旧路径兼容）
	NodeKeyPEM    string
	CACertPEM     string
	Fingerprint   string
	CertExpiresAt time.Time
}

// ListProjectsResult 返回。
type ListProjectsResult struct {
	Projects []*domain.Project
	Total    int
	Page     int
	PageSize int
}

// listMaxPageSize / Default。
const (
	listProjectsDefaultPageSize = 20
	listProjectsMaxPageSize     = 200
)

// service 实现 Service。
type service struct {
	projects repo.ProjectRepository
	members  repo.ProjectMemberRepository
	nodes    repo.NodeRepository
	allowed  repo.AllowedNodesRepository
	tokens   repo.RegistrationTokenRepository
	certs    repo.NodeCertificateRepository
	users    UserLookup
	ca       *pki.CA // 可空：nil 时 Redeem 不签发 cert（与现有测试兼容）
	now      func() time.Time
}

// NewService 构造 tenancy Service。
//
// users 用于 AddProjectMember 校验目标用户合法（role==ProjectAdmin + tenant 匹配）。
// certs / ca 可空：仅在 PR-T4-D2 起的"Redeem 时签发 cert"路径用；nil → 不签发。
func NewService(
	projects repo.ProjectRepository,
	members repo.ProjectMemberRepository,
	nodes repo.NodeRepository,
	allowed repo.AllowedNodesRepository,
	tokens repo.RegistrationTokenRepository,
	certs repo.NodeCertificateRepository,
	users UserLookup,
	ca *pki.CA,
) (Service, error) {
	if projects == nil || members == nil || nodes == nil || allowed == nil || tokens == nil || users == nil {
		return nil, errx.New(errx.ErrInternal, "tenancy.NewService: 依赖不能为 nil")
	}
	return &service{
		projects: projects, members: members, nodes: nodes,
		allowed: allowed, tokens: tokens, certs: certs, users: users,
		ca:  ca,
		now: time.Now,
	}, nil
}

// === CreateProject ===

func (s *service) CreateProject(ctx context.Context, req CreateProjectRequest) (*domain.Project, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "name 不能为空")
	}
	p := &domain.Project{
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Settings:    req.Settings,
		CreatedBy:   req.CreatedBy,
	}
	if err := s.projects.Insert(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// === ListProjects ===

func (s *service) ListProjects(ctx context.Context, req ListProjectsRequest) (*ListProjectsResult, error) {
	if req.PageSize <= 0 {
		req.PageSize = listProjectsDefaultPageSize
	}
	if req.PageSize > listProjectsMaxPageSize {
		req.PageSize = listProjectsMaxPageSize
	}
	if req.Page < 1 {
		req.Page = 1
	}

	// MemberUserID 路径（PA 视角）：先取该用户加入的项目 id 集合，再用集合 +
	// 其他过滤条件查全字段。MVP 实现简单：内存过滤；项目数 <= 1k 量级足够。
	if req.MemberUserID != "" {
		joined, err := s.members.ListProjectIDsByUser(ctx, req.MemberUserID)
		if err != nil {
			return nil, err
		}
		if len(joined) == 0 {
			return &ListProjectsResult{Page: req.Page, PageSize: req.PageSize}, nil
		}
		idset := make(map[string]struct{}, len(joined))
		for _, id := range joined {
			idset[id] = struct{}{}
		}

		// 拉所有匹配 filter 的项目（不分页 → 内存按 id 集合过滤 → 再分页）。
		// 数据量小可接受；规模上来后改 IN 查询或 JOIN。
		all, _, err := s.projects.List(ctx,
			repo.ProjectFilter{
				TenantID: req.TenantID,
				Status:   req.Status,
				Keyword:  req.Keyword,
			},
			repo.Page{Page: 1, PageSize: listProjectsMaxPageSize})
		if err != nil {
			return nil, err
		}
		filtered := make([]*domain.Project, 0, len(joined))
		for _, p := range all {
			if _, ok := idset[p.ID]; ok {
				filtered = append(filtered, p)
			}
		}
		total := len(filtered)
		start := (req.Page - 1) * req.PageSize
		end := start + req.PageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		return &ListProjectsResult{
			Projects: filtered[start:end],
			Total:    total,
			Page:     req.Page,
			PageSize: req.PageSize,
		}, nil
	}

	out, total, err := s.projects.List(ctx,
		repo.ProjectFilter{
			TenantID: req.TenantID,
			Status:   req.Status,
			Keyword:  req.Keyword,
		},
		repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListProjectsResult{
		Projects: out,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

// === GetProject ===

func (s *service) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.GetByID(ctx, id)
}

// === Archive / Unarchive / Delete ===

func (s *service) ArchiveProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.Archive(ctx, id)
}

func (s *service) UnarchiveProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.Unarchive(ctx, id)
}

func (s *service) DeleteProject(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.projects.SoftDelete(ctx, id)
}

// === ProjectMember CRUD ===

// AddProjectMember 校验项目存在 + 用户存在且为 ProjectAdmin + tenant 一致 → Insert。
func (s *service) AddProjectMember(ctx context.Context, req AddProjectMemberRequest) error {
	if strings.TrimSpace(req.ProjectID) == "" || strings.TrimSpace(req.UserID) == "" {
		return errx.New(errx.ErrInvalidInput, "project_id / user_id 不能为空")
	}
	p, err := s.projects.GetByID(ctx, req.ProjectID)
	if err != nil {
		return err
	}
	u, err := s.users.GetByID(ctx, req.UserID)
	if err != nil {
		return err
	}
	if u.Role != identitydomain.RoleProjectAdmin {
		return errx.New(errx.ErrProjectMemberRoleInvalid,
			"仅 PROJECT_ADMIN 可加入项目").
			WithFields("user_role", string(u.Role))
	}
	if u.TenantID != p.TenantID {
		return errx.New(errx.ErrAuthzTenantMismatch,
			"用户与项目不在同一租户").
			WithFields("user_tenant", u.TenantID, "project_tenant", p.TenantID)
	}
	return s.members.Add(ctx, &domain.ProjectMember{
		ProjectID: p.ID,
		UserID:    u.ID,
		TenantID:  p.TenantID,
		AddedBy:   req.AddedBy,
	})
}

// RemoveProjectMember 移除成员。
func (s *service) RemoveProjectMember(ctx context.Context, projectID, userID string) error {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(userID) == "" {
		return errx.New(errx.ErrInvalidInput, "project_id / user_id 不能为空")
	}
	return s.members.Remove(ctx, projectID, userID)
}

// ListProjectMembers 列项目成员。
func (s *service) ListProjectMembers(ctx context.Context, projectID string) ([]*domain.ProjectMember, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	// 先 GetByID 判存在 → 不存在统一 NotFound（防 ID 枚举借列表 RPC）
	if _, err := s.projects.GetByID(ctx, projectID); err != nil {
		return nil, err
	}
	return s.members.ListByProject(ctx, projectID)
}

// === Node CRUD ===

const (
	listNodesDefaultPageSize = 20
	listNodesMaxPageSize     = 200
)

// CreateNode 手动注册节点（MVP；完整 RegistrationToken 流程见 PR-T4-B）。
func (s *service) CreateNode(ctx context.Context, req CreateNodeRequest) (*domain.Node, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "name 不能为空")
	}
	n := &domain.Node{
		TenantID:     req.TenantID,
		Name:         req.Name,
		Version:      req.Version,
		Capabilities: req.Capabilities,
		CreatedBy:    req.CreatedBy,
	}
	if err := s.nodes.Insert(ctx, n); err != nil {
		return nil, err
	}
	return n, nil
}

// ListNodes 列租户内节点。
func (s *service) ListNodes(ctx context.Context, req ListNodesRequest) (*ListNodesResult, error) {
	if req.PageSize <= 0 {
		req.PageSize = listNodesDefaultPageSize
	}
	if req.PageSize > listNodesMaxPageSize {
		req.PageSize = listNodesMaxPageSize
	}
	if req.Page < 1 {
		req.Page = 1
	}
	out, total, err := s.nodes.List(ctx,
		repo.NodeFilter{
			TenantID: req.TenantID,
			Status:   req.Status,
			Keyword:  req.Keyword,
		},
		repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListNodesResult{
		Nodes:    out,
		Total:    total,
		Page:     req.Page,
		PageSize: req.PageSize,
	}, nil
}

func (s *service) GetNode(ctx context.Context, id string) (*domain.Node, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.nodes.GetByID(ctx, id)
}

func (s *service) EnableNode(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	// MVP：从 disabled 恢复时回到 pending（等真节点上报后由 Heartbeat 转 online）
	return s.nodes.UpdateStatus(ctx, id, domain.NodePending)
}

func (s *service) DisableNode(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.nodes.UpdateStatus(ctx, id, domain.NodeDisabled)
}

func (s *service) DeleteNode(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	return s.nodes.SoftDelete(ctx, id)
}

// === AllowedNodes ===

// SetProjectAllowedNodes 全量替换项目白名单。
//
// 流程：
//  1. 校 project 存在（GetByID；soft-deleted 拒）
//  2. 空 ids → ClearAll → 恢复 ALL 默认；返
//  3. 非空 ids → 每个 node 必须存在 + 同 tenant + 未软删；任何一个不满足 → 拒
//  4. allowed.Set 全量替换
func (s *service) SetProjectAllowedNodes(ctx context.Context, req SetProjectAllowedNodesRequest) error {
	if strings.TrimSpace(req.ProjectID) == "" {
		return errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	p, err := s.projects.GetByID(ctx, req.ProjectID)
	if err != nil {
		return err
	}
	if len(req.NodeIDs) == 0 {
		return s.allowed.ClearAll(ctx, req.ProjectID)
	}
	// 去重
	seen := make(map[string]struct{}, len(req.NodeIDs))
	uniq := make([]string, 0, len(req.NodeIDs))
	for _, id := range req.NodeIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		uniq = append(uniq, id)
	}
	// 每个 node 校 tenant + 存在
	for _, id := range uniq {
		n, err := s.nodes.GetByID(ctx, id)
		if err != nil {
			return err
		}
		if n.TenantID != p.TenantID {
			return errx.New(errx.ErrAuthzTenantMismatch,
				"节点与项目不在同一租户").
				WithFields("node_id", id, "node_tenant", n.TenantID,
					"project_tenant", p.TenantID)
		}
	}
	return s.allowed.Set(ctx, req.ProjectID, uniq, req.AddedBy)
}

// GetProjectAllowedNodes 取项目白名单。
func (s *service) GetProjectAllowedNodes(ctx context.Context, projectID string) (domain.AllowedNodes, error) {
	if strings.TrimSpace(projectID) == "" {
		return domain.AllowedNodes{}, errx.New(errx.ErrInvalidInput, "project_id 不能为空")
	}
	if _, err := s.projects.GetByID(ctx, projectID); err != nil {
		return domain.AllowedNodes{}, err
	}
	return s.allowed.Get(ctx, projectID)
}

// IsNodeAllowedForProject Scan 调用。
func (s *service) IsNodeAllowedForProject(ctx context.Context, projectID, nodeID string) (bool, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(nodeID) == "" {
		return false, errx.New(errx.ErrInvalidInput, "project_id / node_id 不能为空")
	}
	return s.allowed.IsAllowed(ctx, projectID, nodeID)
}

// === RegistrationToken ===

// CreateRegistrationToken 生成 plaintext + 入库 hash。
//
// TTL 钳制：
//   - 0 → 默认 1h
//   - < 1m → 拒（防误填）
//   - > 24h → 拒（防长期暴露窗口）
func (s *service) CreateRegistrationToken(ctx context.Context, req CreateRegistrationTokenRequest) (*CreateRegistrationTokenResult, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	if strings.TrimSpace(req.Name) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "name 不能为空")
	}
	ttl := req.TTL
	if ttl == 0 {
		ttl = domain.RegistrationTokenDefaultTTL
	}
	if ttl < domain.RegistrationTokenMinTTL || ttl > domain.RegistrationTokenMaxTTL {
		return nil, errx.New(errx.ErrInvalidInput,
			"ttl 必须在 [1m, 24h]").
			WithFields("got", ttl.String())
	}

	gen, err := tenancycrypto.GenerateNodeToken()
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	tok := &domain.RegistrationToken{
		TenantID:  req.TenantID,
		Name:      req.Name,
		TokenHash: gen.Hash,
		ExpiresAt: now.Add(ttl),
		CreatedBy: req.CreatedBy,
		CreatedAt: now,
	}
	if err := s.tokens.Insert(ctx, tok); err != nil {
		return nil, err
	}
	return &CreateRegistrationTokenResult{
		Token:     tok,
		Plaintext: gen.Plaintext,
	}, nil
}

// ListRegistrationTokens 列租户全部令牌（hash 字段保留；前端不显示）。
func (s *service) ListRegistrationTokens(ctx context.Context, tenantID string) ([]*domain.RegistrationToken, error) {
	if strings.TrimSpace(tenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	return s.tokens.ListByTenant(ctx, tenantID)
}

// RevokeRegistrationToken 撤销令牌（幂等）。
func (s *service) RevokeRegistrationToken(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errx.New(errx.ErrInvalidInput, "token id 不能为空")
	}
	return s.tokens.Revoke(ctx, id)
}

// RedeemRegistrationToken 用 plaintext 兑换 → 创建 Node + 标 used。
//
// 流程：
//  1. plaintext 长度 / 前缀粗校（错码：invalid）
//  2. SHA-256(plaintext) → repo.GetByHash（错码：invalid）
//  3. domain.IsUsable(now)：未用 + 未撤 + 未过期；任一失败 → invalid（混淆）
//  4. CreateNode（pending）；name 已存在 → ErrNodeNameExists 透传
//  5. tokens.MarkUsed（防双花；与 4 不在事务里——若 4 成功 5 失败极少见且仅
//     意味着 token 仍可再用一次，节点已建；MVP 容忍）
func (s *service) RedeemRegistrationToken(ctx context.Context, req RedeemRegistrationTokenRequest) (*RedeemRegistrationTokenResult, error) {
	if !tenancycrypto.IsNodeTokenFormat(req.Plaintext) {
		return nil, errx.New(errx.ErrNodeRegistrationTokenInvalid, "token 格式不合法")
	}
	if strings.TrimSpace(req.NodeName) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "node_name 不能为空")
	}
	hash := tenancycrypto.HashNodeToken(req.Plaintext)
	tok, err := s.tokens.GetByHash(ctx, hash)
	if err != nil {
		// repo 已用 ErrNodeRegistrationTokenInvalid 包装 NotFound
		return nil, err
	}
	if !tok.IsUsable(s.now().UTC()) {
		return nil, errx.New(errx.ErrNodeRegistrationTokenInvalid,
			"token 不可用（已用 / 已撤 / 已过期）")
	}

	// 创建 node 记录
	n := &domain.Node{
		TenantID: tok.TenantID,
		Name:     req.NodeName,
		Version:  req.Version,
		Status:   domain.NodePending, // PR-T4-D3 心跳上线后转 online
	}
	if err := s.nodes.Insert(ctx, n); err != nil {
		return nil, err
	}

	// 标 used；失败仅透传（不回滚 node：MVP 容忍 token 再用，运维可手动 Revoke）
	if err := s.tokens.MarkUsed(ctx, tok.ID); err != nil {
		return nil, err
	}

	res := &RedeemRegistrationTokenResult{Node: n}

	// PR-T4-D2：若注了 CA + certs repo，签发节点 cert + 持久
	if s.ca != nil && s.certs != nil {
		if err := s.issueCertForNode(ctx, n, tok.ID, res); err != nil {
			// cert 签发失败不回滚 node（已 marked used）；让 Agent 重试 / 手动签发
			return nil, err
		}
	}

	return res, nil
}

// issueCertForNode 用 CA 签发节点 client cert + 持久；填充 res 的 cert 相关字段。
func (s *service) issueCertForNode(
	ctx context.Context,
	n *domain.Node,
	tokenID string,
	res *RedeemRegistrationTokenResult,
) error {
	leafKey, err := pki.NewLeafKey()
	if err != nil {
		return err
	}
	leaf, leafCertPEM, err := s.ca.SignLeaf(leafKey.Public(), pki.SignLeafOptions{
		CommonName: n.ID, // CN = node_id（mTLS 校验时反查 node）
		Usage:      pki.LeafUsageClient,
		Validity:   pki.DefaultLeafValidity,
		Now:        s.now(),
	})
	if err != nil {
		return err
	}
	leafKeyPEM, err := pki.MarshalLeafKeyPEM(leafKey)
	if err != nil {
		return err
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.ca.Cert.Raw,
	})

	cert := &domain.NodeCertificate{
		NodeID:        n.ID,
		SerialNumber:  leaf.SerialNumber.String(),
		Fingerprint:   pki.Fingerprint(leaf),
		CommonName:    n.ID,
		CertPEM:       string(leafCertPEM),
		IssuedAt:      leaf.NotBefore.UTC(),
		ExpiresAt:     leaf.NotAfter.UTC(),
		IssuedByToken: tokenID,
	}
	if err := s.certs.Insert(ctx, cert); err != nil {
		return err
	}

	res.NodeCertPEM = string(leafCertPEM)
	res.NodeKeyPEM = string(leafKeyPEM)
	res.CACertPEM = string(caCertPEM)
	res.Fingerprint = cert.Fingerprint
	res.CertExpiresAt = cert.ExpiresAt
	return nil
}

// 占位防止 import 未用（pem 在 issueCertForNode 用；x509 留给 D3 mTLS 校验）。
var _ = x509.ParseCertificate

// Heartbeat（PR-T4-D3）：mTLS 中间件已按 cert fingerprint 反查注 NodeID 到 ctx
// 并填到 req；service 这层只校 nodeID 非空 + 写 last_seen_at。
//
// 与 RedeemRegistrationToken 相反，Heartbeat 是高频调用：MVP 30s/次。
// 任何 DB 故障让 Agent 重试，错码尽量泄露的少（避免被指纹枚举 node_id）。
func (s *service) Heartbeat(ctx context.Context, req HeartbeatRequest) (*HeartbeatResult, error) {
	if strings.TrimSpace(req.NodeID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "heartbeat 缺 node_id")
	}
	now := s.now().UTC()
	if err := s.nodes.TouchLastSeen(ctx, req.NodeID, now); err != nil {
		return nil, err
	}
	// version 上报：仅当 Agent 报了非空值才写（避免空值覆盖 Redeem 时填的版本）。
	if v := strings.TrimSpace(req.Version); v != "" {
		// 复用 GetByID + UpdateStatus 链路成本太高；MVP 用单独的 SQL 路径前
		// 暂略——版本字段后续在状态机迁移时单写一条 Update 即可。这里
		// 不阻塞主路径，version 漂移由 Agent 在 Redeem / 升级时刷新。
		_ = v
	}
	return &HeartbeatResult{
		ServerTime: now,
		Interval:   domain.HeartbeatInterval,
	}, nil
}
