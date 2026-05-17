package export

import (
	"context"
	"strconv"

	"github.com/ffff5sec/RedMatrix/internal/asset"
	"github.com/ffff5sec/RedMatrix/internal/asset/domain"
)

// AssetsResource 把 asset.Service 适配成 export.Resource。
type AssetsResource struct {
	Svc      asset.Service
	PageSize int // 0 = 默认 500
}

// Name 实现 Resource。
func (*AssetsResource) Name() string { return "assets" }

// Columns 实现 Resource；与 ListAssets 返回字段对齐。
func (*AssetsResource) Columns() []string {
	return []string{
		"id", "tenant_id", "project_id", "kind", "value",
		"first_seen", "last_seen", "result_count",
	}
}

// Stream 实现 Resource：按 pageSize 分页拉，逐行 emit。
func (a *AssetsResource) Stream(ctx context.Context, scope Scope, emit func(Row) error) error {
	pageSize := a.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	q := scope.Query
	req := asset.ListRequest{
		ScopedTenantID:   scope.TenantID,
		ScopedProjectIDs: scope.ProjectIDs,
		ProjectID:        firstQuery(q, "project_id"),
		Kind:             domain.Kind(firstQuery(q, "kind")),
		Keyword:          firstQuery(q, "keyword"),
		Page:             1,
		PageSize:         pageSize,
	}
	if v := firstQuery(q, "min_age_days"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			req.MinAgeDays = n
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := a.Svc.ListAssets(ctx, req)
		if err != nil {
			return err
		}
		if res == nil || len(res.Assets) == 0 {
			return nil
		}
		for _, it := range res.Assets {
			row := Row{
				it.ID, it.TenantID, it.ProjectID,
				string(it.Kind), it.Value,
				it.FirstSeen.UTC().Format("2006-01-02T15:04:05Z"),
				it.LastSeen.UTC().Format("2006-01-02T15:04:05Z"),
				strconv.Itoa(it.ResultCount),
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		if len(res.Assets) < pageSize {
			return nil
		}
		req.Page++
	}
}

func firstQuery(q map[string][]string, key string) string {
	if v, ok := q[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}
