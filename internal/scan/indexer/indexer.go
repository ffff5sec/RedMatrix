// Package indexer 把 scan_results 双写到 Elasticsearch（PR-S6）。
//
// 职责：
//   - 启动期 EnsureTemplate：idempotent 创建 index template（mapping + dynamic_templates）
//   - Index(ctx, []*ScanResult)：bulk 写入；空切片 no-op；失败由 caller 决定降级
//
// 不做：
//   - 删 / 改文档（结果只追加，不再变）
//   - 查询（service 仍用 PG repo；查 ES 待 PR-S7 SearchResults）
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
	"github.com/ffff5sec/RedMatrix/internal/storage/es"
)

// IndexName 当前索引名（MVP 单索引；后续按 tenant_id 分区）。
const IndexName = "scan-results"

// templateName 与 IndexName 同前缀，与 index_patterns 关联。
const templateName = "scan-results-template"

// Indexer ES 索引器。esClient 可空（dev / 未装 ES 时 service 退化成 PG-only）。
type Indexer struct {
	es *es.Client
}

// New 构造；esClient 必填。
func New(esClient *es.Client) (*Indexer, error) {
	if esClient == nil || esClient.Client == nil {
		return nil, errx.New(errx.ErrInternal, "scan.indexer.New: es client 不能为 nil")
	}
	return &Indexer{es: esClient}, nil
}

// EnsureTemplate idempotent 写 index template；首启 / 升级时调一次。
//
// mapping 显式声明 task_id / assignment_id / node_id / kind keyword 字段；
// data.* 走 dynamic templates：string → keyword + ignore_above 256，
// number → long / double，便于按 host/port/service 等聚合。
func (i *Indexer) EnsureTemplate(ctx context.Context) error {
	body := map[string]any{
		"index_patterns": []string{IndexName + "*"},
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": 0,
				// PR-S18-B：限 mapping 总字段数，防恶意 / bug agent 上报无限
				// 不同 data.* 键导致 cluster mapping 爆炸（默认 1000 即拒写）
				"index.mapping.total_fields.limit": 1000,
			},
			"mappings": map[string]any{
				"properties": map[string]any{
					"id":            map[string]any{"type": "keyword"},
					"tenant_id":     map[string]any{"type": "keyword"},
					"project_id":    map[string]any{"type": "keyword"},
					"task_id":       map[string]any{"type": "keyword"},
					"assignment_id": map[string]any{"type": "keyword"},
					"node_id":       map[string]any{"type": "keyword"},
					"kind":          map[string]any{"type": "keyword"},
					"created_at":    map[string]any{"type": "date"},
					"data":          map[string]any{"type": "object", "dynamic": true},
					// data_text 是 data.* 的分析副本（copy_to）；让 match 类全文搜索可用，
					// 而 data.* 本身仍按 keyword 精确过滤 / 聚合。
					"data_text": map[string]any{"type": "text"},
				},
				"dynamic_templates": []any{
					map[string]any{
						"data_strings": map[string]any{
							"path_match":         "data.*",
							"match_mapping_type": "string",
							"mapping": map[string]any{
								"type":         "keyword",
								"ignore_above": 1024,
								"copy_to":      "data_text",
							},
						},
					},
				},
			},
		},
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return errx.Wrap(errx.ErrInternal, err, "scan.indexer: encode template")
	}
	req := esapi.IndicesPutIndexTemplateRequest{
		Name: templateName,
		Body: &buf,
	}
	res, err := req.Do(ctx, i.es)
	if err != nil {
		return errx.Wrap(errx.ErrUpstreamTimeout, err, "scan.indexer: put template")
	}
	defer res.Body.Close()
	if res.IsError() {
		return errx.New(errx.ErrUpstreamTimeout, "scan.indexer: put template http "+res.Status())
	}
	return nil
}

// Index 把若干 ScanResult 批量索引到 ES。空切片 no-op。
//
// 用 bulk API；每条 doc id = ScanResult.ID（与 PG 主键一致，重写幂等）。
func (i *Indexer) Index(ctx context.Context, items []*domain.ScanResult) error {
	if len(items) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, it := range items {
		if err := writeBulkLine(&body, it); err != nil {
			return errx.Wrap(errx.ErrInternal, err, "scan.indexer: encode item")
		}
	}
	req := esapi.BulkRequest{
		Index: IndexName,
		Body:  bytes.NewReader(body.Bytes()),
	}
	res, err := req.Do(ctx, i.es)
	if err != nil {
		return errx.Wrap(errx.ErrUpstreamTimeout, err, "scan.indexer: bulk")
	}
	defer res.Body.Close()
	if res.IsError() {
		return errx.New(errx.ErrUpstreamTimeout, "scan.indexer: bulk http "+res.Status())
	}
	// MVP 不解析 errors[]；下次写覆盖即可
	return nil
}

func writeBulkLine(buf *bytes.Buffer, r *domain.ScanResult) error {
	meta := map[string]any{
		"index": map[string]any{"_id": r.ID},
	}
	doc := map[string]any{
		"id":            r.ID,
		"tenant_id":     r.TenantID,
		"project_id":    r.ProjectID,
		"task_id":       r.TaskID,
		"assignment_id": r.AssignmentID,
		"node_id":       r.NodeID,
		"kind":          string(r.Kind),
		"data":          r.Data,
		"created_at":    r.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if err := json.NewEncoder(buf).Encode(meta); err != nil {
		return err
	}
	return json.NewEncoder(buf).Encode(doc)
}

// IsTransient 判定 ES 错是否瞬时（caller 决定是否重试 / 仅日志）。
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "context deadline") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "EOF")
}
