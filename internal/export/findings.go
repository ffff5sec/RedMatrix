package export

import (
	"context"
	"strconv"

	"github.com/ffff5sec/RedMatrix/internal/finding"
)

// FindingsResource 把 finding.Service 适配成 export.Resource。
type FindingsResource struct {
	Svc      finding.Service
	PageSize int // 0 = 默认 500
}

// Name 实现 Resource。
func (*FindingsResource) Name() string { return "findings" }

// Columns 实现 Resource。
func (*FindingsResource) Columns() []string {
	return []string{
		"id", "tenant_id", "project_id", "template_id", "severity",
		"status", "title", "host", "description", "reference",
		"assignee_id", "asset_id", "occurrence_count",
		"first_seen", "last_seen", "created_at",
	}
}

// Stream 实现 Resource。
func (f *FindingsResource) Stream(ctx context.Context, scope Scope, emit func(Row) error) error {
	// PA 0 项目短路（List 已有同行为，提早 return 省一次 RPC）
	if scope.ProjectIDs != nil && len(scope.ProjectIDs) == 0 {
		return nil
	}
	pageSize := f.PageSize
	if pageSize <= 0 {
		pageSize = 500
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	q := scope.Query
	req := finding.ListFindingsRequest{
		TenantID:    scope.TenantID,
		ProjectIDs:  scope.ProjectIDs,
		ProjectID:   firstQuery(q, "project_id"),
		Status:      firstQuery(q, "status"),
		Severity:    firstQuery(q, "severity"),
		AssigneeID:  firstQuery(q, "assignee_id"),
		Keyword:     firstQuery(q, "keyword"),
		MinSeverity: firstQuery(q, "min_severity"),
		Page:        1,
		PageSize:    pageSize,
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := f.Svc.ListFindings(ctx, req)
		if err != nil {
			return err
		}
		if res == nil || len(res.Findings) == 0 {
			return nil
		}
		for _, it := range res.Findings {
			row := Row{
				it.ID, it.TenantID, it.ProjectID, it.TemplateID, string(it.Severity),
				string(it.Status), it.Title, it.Host, it.Description, it.Reference,
				strPtr(it.AssigneeID), strPtr(it.AssetID),
				strconv.Itoa(it.OccurrenceCount),
				it.FirstSeenAt.UTC().Format("2006-01-02T15:04:05Z"),
				it.LastSeenAt.UTC().Format("2006-01-02T15:04:05Z"),
				it.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			}
			if err := emit(row); err != nil {
				return err
			}
		}
		if len(res.Findings) < pageSize {
			return nil
		}
		req.Page++
	}
}

func strPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
