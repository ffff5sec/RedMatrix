// Package audit 审计日志 service（PR-S33）。
//
// 业务流：
//   - 上游模块（identity / scan / finding / pluginpkg）调 service.Log(ev) 写一条
//   - service 算 prev_hash（取该 tenant 最新一条）+ hash → INSERT
//   - 失败仅 log，不阻断上游主流程（审计是观测，不是事务）
//
// 校验：
//   - VerifyChain(tenantID, from, to) 拉一段连续 audit 行 → 重算 hash 与列比对
//   - 跑慢；MVP 限 limit=500 行；后续可改成游标
package audit

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/audit/domain"
	"github.com/ffff5sec/RedMatrix/internal/audit/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// LogEvent service.Log 入参。
type LogEvent struct {
	Action        domain.ActionKind
	ResourceKind  string
	ResourceID    string
	TenantID      string
	ProjectID     string
	ActorUserID   string
	ActorUsername string
	ActorIP       string
	UserAgent     string
	Payload       map[string]any
}

// ListLogsRequest 列表入参。
type ListLogsRequest struct {
	TenantID     string
	ProjectID    string
	ActorUserID  string
	Action       string
	ResourceKind string
	ResourceID   string
	TimeFrom     *time.Time
	TimeTo       *time.Time
	Page         int
	PageSize     int
}

// ListLogsResult 分页结果。
type ListLogsResult struct {
	Logs     []*domain.AuditLog
	Total    int
	Page     int
	PageSize int
}

// VerifyChainRequest 校验入参。
type VerifyChainRequest struct {
	TenantID string
	TimeFrom time.Time
	TimeTo   time.Time
	Limit    int
}

// VerifyChainResult 校验结果。
type VerifyChainResult struct {
	OK           bool
	Total        int    // 实际扫描行数
	BreakAtIndex int    // ok=false 时第一个不连续 index（基于 ASC 切片）
	BreakAtID    string // 对应的 audit.id
}

// Service audit 模块对外接口。
type Service interface {
	Log(ctx context.Context, ev LogEvent) error
	GetLog(ctx context.Context, id string) (*domain.AuditLog, error)
	ListLogs(ctx context.Context, req ListLogsRequest) (*ListLogsResult, error)
	VerifyChain(ctx context.Context, req VerifyChainRequest) (*VerifyChainResult, error)
}

// Logger 让 service 失败可观测。
type Logger interface {
	LogError(ctx context.Context, msg string, err error, kv ...any)
}

type service struct {
	repo   repo.Repository
	logger Logger
	now    func() time.Time

	// 简单 in-process 锁：同 tenant 串行写以保 prev_hash 一致。
	// MVP 简化：单实例部署够用；多实例需移到 PG advisory lock 或 unique 索引重试。
	mu       sync.Mutex
	tenantMu map[string]*sync.Mutex
}

// New 构造 Service。
func New(r repo.Repository, logger Logger) (Service, error) {
	if r == nil {
		return nil, errx.New(errx.ErrInternal, "audit.New: repo 不能为 nil")
	}
	return &service{
		repo: r, logger: logger,
		now:      time.Now,
		tenantMu: map[string]*sync.Mutex{},
	}, nil
}

// lockTenant 拿到 per-tenant 的写互斥锁。
func (s *service) lockTenant(tenant string) func() {
	s.mu.Lock()
	m, ok := s.tenantMu[tenant]
	if !ok {
		m = &sync.Mutex{}
		s.tenantMu[tenant] = m
	}
	s.mu.Unlock()
	m.Lock()
	return m.Unlock
}

func (s *service) Log(ctx context.Context, ev LogEvent) error {
	if strings.TrimSpace(ev.TenantID) == "" {
		return errx.New(errx.ErrInvalidInput, "audit: tenant_id 不能为空")
	}
	if !ev.Action.Valid() {
		return errx.New(errx.ErrInvalidInput, "audit: action 不合法").
			WithFields("got", string(ev.Action))
	}

	unlock := s.lockTenant(ev.TenantID)
	defer unlock()

	prev, _, err := s.repo.LatestHash(ctx, ev.TenantID)
	if err != nil {
		return err
	}

	row := &domain.AuditLog{
		ActorUsername: ev.ActorUsername,
		ActorIP:       ev.ActorIP,
		UserAgent:     ev.UserAgent,
		Action:        ev.Action,
		ResourceKind:  ev.ResourceKind,
		ResourceID:    ev.ResourceID,
		TenantID:      ev.TenantID,
		Payload:       ev.Payload,
		CreatedAt:     s.now().UTC(),
	}
	if strings.TrimSpace(ev.ActorUserID) != "" {
		uid := ev.ActorUserID
		row.ActorUserID = &uid
	}
	if strings.TrimSpace(ev.ProjectID) != "" {
		pid := ev.ProjectID
		row.ProjectID = &pid
	}
	domain.ComputeForLog(row, prev)

	if err := s.repo.Insert(ctx, row); err != nil {
		if s.logger != nil {
			s.logger.LogError(ctx, "audit: insert failed", err,
				"tenant_id", ev.TenantID, "action", string(ev.Action))
		}
		return err
	}
	return nil
}

func (s *service) GetLog(ctx context.Context, id string) (*domain.AuditLog, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *service) ListLogs(ctx context.Context, req ListLogsRequest) (*ListLogsResult, error) {
	out, total, err := s.repo.List(ctx, repo.LogFilter{
		TenantID:     req.TenantID,
		ProjectID:    req.ProjectID,
		ActorUserID:  req.ActorUserID,
		Action:       req.Action,
		ResourceKind: req.ResourceKind,
		ResourceID:   req.ResourceID,
		TimeFrom:     req.TimeFrom,
		TimeTo:       req.TimeTo,
	}, repo.Page{Page: req.Page, PageSize: req.PageSize})
	if err != nil {
		return nil, err
	}
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	return &ListLogsResult{Logs: out, Total: total, Page: page, PageSize: pageSize}, nil
}

func (s *service) VerifyChain(ctx context.Context, req VerifyChainRequest) (*VerifyChainResult, error) {
	if strings.TrimSpace(req.TenantID) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "tenant_id 不能为空")
	}
	from, to := req.TimeFrom, req.TimeTo
	if from.IsZero() {
		from = s.now().Add(-30 * 24 * time.Hour)
	}
	if to.IsZero() {
		to = s.now()
	}
	rows, err := s.repo.ListSegmentASC(ctx, req.TenantID, from, to, req.Limit)
	if err != nil {
		return nil, err
	}
	ok, breakAt := domain.VerifyChainSegment(rows)
	res := &VerifyChainResult{OK: ok, Total: len(rows), BreakAtIndex: breakAt}
	if !ok && breakAt >= 0 && breakAt < len(rows) {
		res.BreakAtID = rows[breakAt].ID
	}
	return res, nil
}
