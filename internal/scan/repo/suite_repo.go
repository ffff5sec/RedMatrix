// Package repo：扫描套件（PR-S23）持久层接口。
package repo

import (
	"context"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// SuiteFilter ListSuites 查询过滤。
type SuiteFilter struct {
	TenantID  string // 必填
	ProjectID string // 空 = 含跨项目套件 + 所有项目；非空 = 该项目 + 跨项目（project_id IS NULL）
	Keyword   string // 空 = 不过滤；name ILIKE
}

// SuiteRepository 是 scan_suites 表的持久层。
type SuiteRepository interface {
	Insert(ctx context.Context, s *domain.ScanSuite) error
	GetByID(ctx context.Context, id string) (*domain.ScanSuite, error)
	List(ctx context.Context, filter SuiteFilter, page Page) ([]*domain.ScanSuite, int, error)
	SoftDelete(ctx context.Context, id string) error
}

// SuiteRunFilter ListSuiteRuns 查询过滤。
type SuiteRunFilter struct {
	TenantID  string
	ProjectID string
	SuiteID   string
}

// SuiteRunRepository 是 scan_suite_runs 表的持久层。
type SuiteRunRepository interface {
	Insert(ctx context.Context, r *domain.ScanSuiteRun) error
	GetByID(ctx context.Context, id string) (*domain.ScanSuiteRun, error)
	List(ctx context.Context, filter SuiteRunFilter, page Page) ([]*domain.ScanSuiteRun, int, error)
	// UpdateStatus 推进 status；finishedAt 非空时写 finished_at（终态时调用）。
	UpdateStatus(ctx context.Context, id string, status domain.SuiteRunStatus, finished bool) error
}
