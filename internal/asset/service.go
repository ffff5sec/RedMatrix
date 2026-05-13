// Package asset 是资产视图业务流（PR-S8）。
//
// Asset 由 scan_results 派生：每次 ReportResults 后，scan service 把结果
// 转成 asset 行调 UpsertFromResults，按 (tenant, project, kind, value)
// UPSERT 累计。
package asset

import (
	"context"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
	"github.com/ffff5sec/RedMatrix/internal/asset/repo"
	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/log"
)

// ResultInput 把 scan 模块的 result 行抽象成派生输入。
//
// 解耦：asset 模块不直接 import scan domain，避免循环。caller（scan service）
// 把 ScanResult 拍成 ResultInput 切片传过来。
type ResultInput struct {
	TenantID  string
	ProjectID string
	// Kind 与 scan task.kind 同：port_scan / web_crawl / subdomain / fingerprint
	Kind string
	// Data 原始结果 payload；asset 派生函数按 Kind 取对应字段
	Data map[string]any
}

// Service 资产业务流。
type Service interface {
	// UpsertFromResults 由 scan.service 在 ReportResults 后同步调；
	// 把若干 result 行按 kind 派生成 asset 行 UPSERT。空切片 no-op。
	UpsertFromResults(ctx context.Context, items []ResultInput) error

	// ListAssets 列资产；handler 注 RBAC 后调。
	ListAssets(ctx context.Context, req ListRequest) (*ListResponse, error)

	// GetAsset 单条；不存在返 ErrAssetNotFound。
	GetAsset(ctx context.Context, id string) (*domain.Asset, error)
}

// ListRequest 列表入参。
type ListRequest struct {
	Kind      domain.Kind
	ProjectID string
	Keyword   string
	Page      int
	PageSize  int

	// MinAgeDays（PR-S31 freshness）：> 0 时仅返 last_seen ≤ now - 此天数 的资产。
	// 0 = 不过滤；用于 "最近 N 天未扫" 视图。
	MinAgeDays int

	// RBAC（handler 注入）
	ScopedTenantID   string
	ScopedProjectIDs []string // nil = 不限；空切片 = PA 0 项目，service 直返空
}

// ListResponse 列表返回。
type ListResponse struct {
	Assets   []*domain.Asset
	Total    int
	Page     int
	PageSize int
}

type service struct {
	repo   repo.Repository
	logger *log.Logger
	now    func() time.Time
}

// NewService 构造。
func NewService(r repo.Repository, logger *log.Logger) (Service, error) {
	if r == nil {
		return nil, errx.New(errx.ErrInternal, "asset.NewService: repo 不能为 nil")
	}
	return &service{repo: r, logger: logger, now: time.Now}, nil
}

// UpsertFromResults：把若干 ResultInput 派生为 Asset 后 UpsertBulk。
//
// 派生规则：
//   - port_scan / fingerprint: data.host / data.target → KindHost
//   - subdomain:               data.name → KindSubdomain
//   - web_crawl:               data.url  → KindURL（去 query / fragment）
//
// 一条 result 派生 0 / 1 条 asset；同一批多条派生到同 (kind, value) 时
// 合并 delta（避免一次 ReportResults 内重复 UPSERT 数据库）。
func (s *service) UpsertFromResults(ctx context.Context, items []ResultInput) error {
	if len(items) == 0 {
		return nil
	}
	// 先在内存里合并（key=tenant|project|kind|value），减少 SQL 行数
	type key struct{ tenant, project, kind, value string }
	merged := map[key]*domain.Asset{}
	for _, it := range items {
		k, v, ok := derive(it)
		if !ok {
			continue
		}
		mk := key{it.TenantID, it.ProjectID, string(k), v}
		if a, exists := merged[mk]; exists {
			a.ResultCount++
			continue
		}
		merged[mk] = &domain.Asset{
			TenantID:    it.TenantID,
			ProjectID:   it.ProjectID,
			Kind:        k,
			Value:       v,
			ResultCount: 1,
		}
	}
	if len(merged) == 0 {
		return nil
	}
	rows := make([]*domain.Asset, 0, len(merged))
	for _, a := range merged {
		rows = append(rows, a)
	}
	return s.repo.UpsertBulk(ctx, rows)
}

// derive 从一条 ResultInput 派生 asset 的 (kind, value)。
// 不能派生时返 (..., false)；caller 静默跳过。
func derive(in ResultInput) (domain.Kind, string, bool) {
	if in.Data == nil {
		return "", "", false
	}
	switch in.Kind {
	case "port_scan":
		if h, ok := in.Data["host"].(string); ok {
			v := domain.NormalizeHost(h)
			if v != "" {
				return domain.KindHost, v, true
			}
		}
	case "fingerprint":
		// fingerprint 的 target 可能是 host 或 url
		if t, ok := in.Data["target"].(string); ok {
			if u := domain.NormalizeURL(t); u != "" {
				return domain.KindURL, u, true
			}
			if h := domain.NormalizeHost(t); h != "" {
				return domain.KindHost, h, true
			}
		}
	case "subdomain":
		if n, ok := in.Data["name"].(string); ok {
			v := domain.NormalizeHost(n)
			if v != "" {
				return domain.KindSubdomain, v, true
			}
		}
	case "web_crawl":
		if u, ok := in.Data["url"].(string); ok {
			v := domain.NormalizeURL(u)
			if v != "" {
				return domain.KindURL, v, true
			}
		}
	}
	return "", "", false
}

// ListAssets 透传 + RBAC 防越权 +分页归一。
func (s *service) ListAssets(ctx context.Context, req ListRequest) (*ListResponse, error) {
	// PA 0 项目 → 短路返空
	if req.ScopedProjectIDs != nil && len(req.ScopedProjectIDs) == 0 {
		page, size := normalizePage(req.Page, req.PageSize)
		return &ListResponse{Assets: []*domain.Asset{}, Page: page, PageSize: size}, nil
	}
	// 防越权：用户传的 ProjectID 必须命中 ScopedProjectIDs
	if req.ProjectID != "" && req.ScopedProjectIDs != nil {
		ok := false
		for _, p := range req.ScopedProjectIDs {
			if p == req.ProjectID {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errx.New(errx.ErrProjectAccessDenied,
				"无权访问该项目").WithFields("project_id", req.ProjectID)
		}
	}
	f := repo.Filter{
		TenantID:   req.ScopedTenantID,
		ProjectID:  req.ProjectID,
		ProjectIDs: req.ScopedProjectIDs,
		Kind:       req.Kind,
		Keyword:    strings.TrimSpace(req.Keyword),
	}
	if req.MinAgeDays > 0 {
		cutoff := s.now().Add(-time.Duration(req.MinAgeDays) * 24 * time.Hour)
		f.LastSeenBefore = &cutoff
	}
	page, size := normalizePage(req.Page, req.PageSize)
	list, total, err := s.repo.List(ctx, f, repo.Page{Page: page, PageSize: size})
	if err != nil {
		return nil, err
	}
	return &ListResponse{Assets: list, Total: total, Page: page, PageSize: size}, nil
}

func (s *service) GetAsset(ctx context.Context, id string) (*domain.Asset, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "asset.id 不能为空")
	}
	return s.repo.GetByID(ctx, id)
}

func normalizePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 50
	}
	if size > 200 {
		size = 200
	}
	return page, size
}
