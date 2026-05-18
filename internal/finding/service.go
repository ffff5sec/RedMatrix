// Package finding 漏洞工作流 service（PR-S26）。
//
// 业务流：
//   - 自动入口：scan.ReportResults 高危 result（nuclei severity ∈ high/critical）→
//     UpsertFromResult → 按 dedup_key 去重，新建 / 累加 occurrence_count
//   - 手工入口：List / Get / Transition / Comment / Assign / ListEvents
package finding

import (
	"context"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/finding/domain"
	"github.com/ffff5sec/RedMatrix/internal/finding/repo"
)

// Service finding 模块对外接口。
type Service interface {
	// === 列 / 查 ===
	ListFindings(ctx context.Context, req ListFindingsRequest) (*ListFindingsResult, error)
	GetFinding(ctx context.Context, id string) (*domain.Finding, error)
	ListEvents(ctx context.Context, findingID string) ([]*domain.FindingEvent, error)

	// === 状态机 / 评论 / 指派 ===
	Transition(ctx context.Context, req TransitionRequest) (*domain.Finding, error)
	Comment(ctx context.Context, req CommentRequest) (*domain.FindingEvent, error)
	Assign(ctx context.Context, req AssignRequest) (*domain.Finding, error)

	// === 自动入口（scan 钩子调）===
	UpsertFromResult(ctx context.Context, req UpsertFromResultRequest) (*domain.Finding, bool, error)
}

// ListFindingsRequest 列入参。
type ListFindingsRequest struct {
	TenantID    string
	ProjectID   string
	ProjectIDs  []string // PA 路径
	Status      string
	Severity    string
	AssigneeID  string
	Keyword     string
	MinSeverity string
	AssetID     string // PR-S70 按资产 ID 过滤
	Page        int
	PageSize    int
}

// ListFindingsResult 分页结果。
type ListFindingsResult struct {
	Findings []*domain.Finding
	Total    int
	Page     int
	PageSize int
}

// TransitionRequest 状态转移入参。
type TransitionRequest struct {
	ID      string
	To      domain.FindingStatus
	ActorID string
	Comment string // 可选；非空时一并落 comment 事件
}

// CommentRequest 评论入参。
type CommentRequest struct {
	FindingID string
	ActorID   string
	Body      string
}

// AssignRequest 指派入参。
type AssignRequest struct {
	ID         string
	ActorID    string
	AssigneeID *string // nil = 取消指派
}

// UpsertFromResultRequest 来自 scan 钩子的自动入参。
type UpsertFromResultRequest struct {
	TenantID    string
	ProjectID   string
	TemplateID  string
	Host        string
	Severity    domain.Severity
	Title       string
	Description string
	Reference   string
	ResultID    *string // 来源 scan_result.id
	AssetID     *string // PR-S70：可选；scan_hook 用 asset.LookupByHost 查到后传入
}

// Deps service 依赖。
type Deps struct {
	Findings repo.FindingRepository
	Events   repo.EventRepository
}

type service struct {
	findings repo.FindingRepository
	events   repo.EventRepository
	now      func() time.Time
}

// New 构造 Service。
func New(d Deps) (Service, error) {
	if d.Findings == nil || d.Events == nil {
		return nil, errx.New(errx.ErrInternal, "finding.New: repos 不能为空")
	}
	return &service{findings: d.Findings, events: d.Events, now: time.Now}, nil
}

// === 列 / 查 ===

func (s *service) ListFindings(ctx context.Context, req ListFindingsRequest) (*ListFindingsResult, error) {
	out, total, err := s.findings.List(ctx, repo.FindingFilter{
		TenantID:    req.TenantID,
		ProjectID:   req.ProjectID,
		ProjectIDs:  req.ProjectIDs,
		Status:      req.Status,
		Severity:    req.Severity,
		AssigneeID:  req.AssigneeID,
		Keyword:     req.Keyword,
		MinSeverity: req.MinSeverity,
		AssetID:     req.AssetID, // PR-S70
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	return &ListFindingsResult{
		Findings: out, Total: total,
		Page: maxInt(req.Page, 1), PageSize: pageSizeOrDefault(req.PageSize, 50),
	}, nil
}

func (s *service) GetFinding(ctx context.Context, id string) (*domain.Finding, error) {
	return s.findings.GetByID(ctx, id)
}

func (s *service) ListEvents(ctx context.Context, findingID string) ([]*domain.FindingEvent, error) {
	if strings.TrimSpace(findingID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "finding_id 不能为空")
	}
	// 校 finding 存在
	if _, err := s.findings.GetByID(ctx, findingID); err != nil {
		return nil, err
	}
	return s.events.ListByFinding(ctx, findingID)
}

// === 状态机 / 评论 / 指派 ===

func (s *service) Transition(ctx context.Context, req TransitionRequest) (*domain.Finding, error) {
	if strings.TrimSpace(req.ID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	if !req.To.Valid() {
		return nil, errx.New(errx.ErrInvalidInput, "to_status 不合法").
			WithFields("got", string(req.To))
	}
	cur, err := s.findings.GetByID(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	if !domain.CanTransition(cur.Status, req.To) {
		return nil, errx.New(errx.ErrFindingInvalidTransition,
			"不允许的状态转移").
			WithFields("from", string(cur.Status), "to", string(req.To))
	}

	// PR-S42 CAS：原子检查 status = cur.Status 才改为 req.To。
	// 消除两并发 Transition 都过 CanTransition 而互相覆盖的 TOCTOU。
	matched, err := s.findings.UpdateStatusCAS(ctx, req.ID, cur.Status, req.To)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, errx.New(errx.ErrFindingInvalidTransition,
			"不允许的状态转移（并发已改）").
			WithFields("from", string(cur.Status), "to", string(req.To))
	}

	from := cur.Status
	to := req.To
	ev := &domain.FindingEvent{
		FindingID:  req.ID,
		ActorID:    nullablePtr(req.ActorID),
		Kind:       domain.EventStatusChange,
		FromStatus: &from,
		ToStatus:   &to,
		Body:       req.Comment,
	}
	if err := s.events.Insert(ctx, ev); err != nil {
		return nil, err
	}
	cur.Status = req.To
	cur.UpdatedAt = s.now()
	return cur, nil
}

func (s *service) Comment(ctx context.Context, req CommentRequest) (*domain.FindingEvent, error) {
	if strings.TrimSpace(req.FindingID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "finding_id 不能为空")
	}
	if strings.TrimSpace(req.Body) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "comment 不能为空")
	}
	if _, err := s.findings.GetByID(ctx, req.FindingID); err != nil {
		return nil, err
	}
	ev := &domain.FindingEvent{
		FindingID: req.FindingID,
		ActorID:   nullablePtr(req.ActorID),
		Kind:      domain.EventComment,
		Body:      req.Body,
	}
	if err := s.events.Insert(ctx, ev); err != nil {
		return nil, err
	}
	return ev, nil
}

func (s *service) Assign(ctx context.Context, req AssignRequest) (*domain.Finding, error) {
	if strings.TrimSpace(req.ID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "id 不能为空")
	}
	cur, err := s.findings.GetByID(ctx, req.ID)
	if err != nil {
		return nil, err
	}
	// PR-S42 CAS：原子检查 assignee_id = cur.AssigneeID 才改。
	// 两并发 Assign(A) / Assign(B) 都基于 Get 的 from-assignee，CAS 让后到者
	// matched=false 返 invalid，不会写入误导性的 event 流水。
	matched, err := s.findings.UpdateAssigneeCAS(ctx, req.ID, cur.AssigneeID, req.AssigneeID)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, errx.New(errx.ErrFindingInvalidTransition,
			"指派失败（并发已改 assignee，请重试）").
			WithFields("id", req.ID)
	}
	ev := &domain.FindingEvent{
		FindingID:    req.ID,
		ActorID:      nullablePtr(req.ActorID),
		Kind:         domain.EventAssigneeChange,
		FromAssignee: cur.AssigneeID,
		ToAssignee:   req.AssigneeID,
	}
	if err := s.events.Insert(ctx, ev); err != nil {
		return nil, err
	}
	cur.AssigneeID = req.AssigneeID
	cur.UpdatedAt = s.now()
	return cur, nil
}

// === 自动入口 ===

func (s *service) UpsertFromResult(ctx context.Context, req UpsertFromResultRequest) (*domain.Finding, bool, error) {
	if strings.TrimSpace(req.TenantID) == "" || strings.TrimSpace(req.ProjectID) == "" {
		return nil, false, errx.New(errx.ErrInvalidInput, "tenant_id / project_id 不能为空")
	}
	if strings.TrimSpace(req.TemplateID) == "" || strings.TrimSpace(req.Host) == "" {
		return nil, false, errx.New(errx.ErrInvalidInput, "template_id / host 不能为空")
	}
	dedupKey := domain.MakeDedupKey(req.TemplateID, req.Host)

	f := &domain.Finding{
		TenantID:       req.TenantID,
		ProjectID:      req.ProjectID,
		DedupKey:       dedupKey,
		TemplateID:     req.TemplateID,
		SourceResultID: req.ResultID,
		AssetID:        req.AssetID, // PR-S70：可选；scan_hook 查到则带入
		Severity:       req.Severity,
		Title:          req.Title,
		Host:           req.Host,
		Description:    req.Description,
		Reference:      req.Reference,
		Status:         domain.FindingOpen,
	}
	out, inserted, err := s.findings.Upsert(ctx, f)
	if err != nil {
		return nil, false, err
	}

	// 记 event：created 或 occurrence
	kind := domain.EventOccurrence
	if inserted {
		kind = domain.EventCreated
	}
	_ = s.events.Insert(ctx, &domain.FindingEvent{
		FindingID: out.ID,
		Kind:      kind,
		// ActorID nil = system
		Body: req.Title,
	})
	return out, inserted, nil
}

// === helpers ===

func nullablePtr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func pageSizeOrDefault(s, def int) int {
	if s <= 0 {
		return def
	}
	return s
}
