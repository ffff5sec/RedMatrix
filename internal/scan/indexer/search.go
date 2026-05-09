// search.go: ES 检索（PR-S7 SearchResults 后端）。
//
// Search 输入 SearchQuery（service 已做权限收紧 → ProjectIDs 注入）；
// ES 端用 bool 的 filter 子句拼 term/terms/range，关键字走 match on data_text。
// 聚合返 kind / node_id 两个 terms agg。
package indexer

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

const (
	defaultSearchSize = 50
	maxSearchSize     = 100
	maxSearchFrom     = 10000 // ES from + size <= 10000 限制
	facetTopN         = 20
)

// SearchQuery 是 indexer.Search 的入参（与 proto.SearchResultsRequest 解耦）。
//
// service 层做权限收紧后填这里：
//   - SA: 不传任何 ID 限制
//   - TA: TenantID 必填
//   - PA: TenantID + ProjectIDs（用户加入的项目）必填；空 ProjectIDs 直接返空
type SearchQuery struct {
	Keyword  string
	TenantID string
	// ProjectIDs PA 权限收紧用：terms 过滤；为 nil/空 表示不限项目（SA / TA 路径）。
	// 显式传空切片 = "我加入了 0 个项目"，service 层应直接短路返空（不会调到这里）。
	ProjectIDs []string
	ProjectID  string // 单项目过滤（来自前端 filter chip）
	NodeID     string
	TaskID     string
	Kind       string
	TimeFrom   *time.Time
	TimeTo     *time.Time
	Page       int
	PageSize   int
}

// SearchResultPage 是返回；items 已是 *domain.ScanResult，service 层直接转 proto。
type SearchResultPage struct {
	Items    []*domain.ScanResult
	Total    int
	Page     int
	PageSize int
	Facets   []Facet
}

// Facet 一个聚合维度的 top-N。
type Facet struct {
	Field   string
	Buckets []FacetBucket
}

// FacetBucket key+count。
type FacetBucket struct {
	Key   string
	Count int
}

// Search 执行检索。
func (i *Indexer) Search(ctx context.Context, q SearchQuery) (*SearchResultPage, error) {
	page, size := NormalizePage(q.Page, q.PageSize)
	from := (page - 1) * size
	if from+size > maxSearchFrom {
		return nil, errx.New(errx.ErrInvalidInput,
			"search 分页过深（page * page_size 超 10000）；请用更精确过滤")
	}

	body := buildSearchBody(q, from, size)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "scan.indexer: encode search body")
	}

	req := esapi.SearchRequest{
		Index: []string{IndexName},
		Body:  &buf,
		// track_total_hits=true 让 hits.total 带 value，前端能算总页数
		TrackTotalHits: true,
	}
	res, err := req.Do(ctx, i.es)
	if err != nil {
		return nil, errx.Wrap(errx.ErrUpstreamTimeout, err, "scan.indexer: search")
	}
	defer res.Body.Close()
	// 索引尚未建（首次没人写过）→ 返空页，不算错
	if res.StatusCode == 404 {
		return &SearchResultPage{Items: []*domain.ScanResult{}, Page: page, PageSize: size}, nil
	}
	if res.IsError() {
		return nil, errx.New(errx.ErrUpstreamTimeout, "scan.indexer: search http "+res.Status())
	}

	var raw esSearchResponse
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "scan.indexer: decode search response")
	}
	return parseSearchResponse(&raw, page, size), nil
}

// buildSearchBody 拼 ES query body。filter 子句不打分，性能好；keyword 走 must 打分排序更直觉。
func buildSearchBody(q SearchQuery, from, size int) map[string]any {
	filters := []any{}
	if s := strings.TrimSpace(q.TenantID); s != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"tenant_id": s}})
	}
	if s := strings.TrimSpace(q.ProjectID); s != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"project_id": s}})
	} else if len(q.ProjectIDs) > 0 {
		filters = append(filters, map[string]any{"terms": map[string]any{"project_id": q.ProjectIDs}})
	}
	if s := strings.TrimSpace(q.NodeID); s != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"node_id": s}})
	}
	if s := strings.TrimSpace(q.TaskID); s != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"task_id": s}})
	}
	if s := strings.TrimSpace(q.Kind); s != "" {
		filters = append(filters, map[string]any{"term": map[string]any{"kind": s}})
	}
	if q.TimeFrom != nil || q.TimeTo != nil {
		rng := map[string]any{}
		if q.TimeFrom != nil {
			rng["gte"] = q.TimeFrom.UTC().Format(time.RFC3339)
		}
		if q.TimeTo != nil {
			rng["lte"] = q.TimeTo.UTC().Format(time.RFC3339)
		}
		filters = append(filters, map[string]any{"range": map[string]any{"created_at": rng}})
	}

	boolClause := map[string]any{}
	if len(filters) > 0 {
		boolClause["filter"] = filters
	}
	if kw := strings.TrimSpace(q.Keyword); kw != "" {
		boolClause["must"] = []any{
			map[string]any{
				"match": map[string]any{
					"data_text": map[string]any{
						"query":    kw,
						"operator": "and",
					},
				},
			},
		}
	}

	body := map[string]any{
		"from": from,
		"size": size,
		"sort": []any{
			map[string]any{"created_at": map[string]any{"order": "desc"}},
		},
		"aggs": map[string]any{
			"by_kind": map[string]any{
				"terms": map[string]any{"field": "kind", "size": facetTopN},
			},
			"by_node": map[string]any{
				"terms": map[string]any{"field": "node_id", "size": facetTopN},
			},
		},
	}
	if len(boolClause) > 0 {
		body["query"] = map[string]any{"bool": boolClause}
	} else {
		body["query"] = map[string]any{"match_all": map[string]any{}}
	}
	return body
}

func parseSearchResponse(raw *esSearchResponse, page, size int) *SearchResultPage {
	out := &SearchResultPage{
		Items:    make([]*domain.ScanResult, 0, len(raw.Hits.Hits)),
		Total:    raw.Hits.Total.Value,
		Page:     page,
		PageSize: size,
	}
	for i := range raw.Hits.Hits {
		h := &raw.Hits.Hits[i]
		r := &domain.ScanResult{
			ID:           h.Source.ID,
			TenantID:     h.Source.TenantID,
			ProjectID:    h.Source.ProjectID,
			TaskID:       h.Source.TaskID,
			AssignmentID: h.Source.AssignmentID,
			NodeID:       h.Source.NodeID,
			Kind:         domain.TaskKind(h.Source.Kind),
			Data:         h.Source.Data,
		}
		if h.Source.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339Nano, h.Source.CreatedAt); err == nil {
				r.CreatedAt = t
			}
		}
		if r.Data == nil {
			r.Data = map[string]any{}
		}
		out.Items = append(out.Items, r)
	}
	if len(raw.Aggs.ByKind.Buckets) > 0 {
		out.Facets = append(out.Facets, bucketsToFacet("kind", raw.Aggs.ByKind.Buckets))
	}
	if len(raw.Aggs.ByNode.Buckets) > 0 {
		out.Facets = append(out.Facets, bucketsToFacet("node_id", raw.Aggs.ByNode.Buckets))
	}
	return out
}

func bucketsToFacet(field string, bs []esBucket) Facet {
	out := Facet{Field: field, Buckets: make([]FacetBucket, 0, len(bs))}
	for _, b := range bs {
		out.Buckets = append(out.Buckets, FacetBucket{Key: b.Key, Count: b.DocCount})
	}
	return out
}

func NormalizePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = defaultSearchSize
	}
	if size > maxSearchSize {
		size = maxSearchSize
	}
	return page, size
}

// === ES response 解码结构 ===

type esSearchResponse struct {
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []struct {
			Source esDoc `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
	Aggs struct {
		ByKind struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"by_kind"`
		ByNode struct {
			Buckets []esBucket `json:"buckets"`
		} `json:"by_node"`
	} `json:"aggregations"`
}

type esDoc struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	ProjectID    string         `json:"project_id"`
	TaskID       string         `json:"task_id"`
	AssignmentID string         `json:"assignment_id"`
	NodeID       string         `json:"node_id"`
	Kind         string         `json:"kind"`
	Data         map[string]any `json:"data"`
	CreatedAt    string         `json:"created_at"`
}

type esBucket struct {
	Key      string `json:"key"`
	DocCount int    `json:"doc_count"`
}
