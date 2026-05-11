package scan

import (
	"time"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
)

// ResultBatchInsertedEvent —— ReportResults 在同一 PG TX 内 PublishTx 的事件，
// relay 异步消费后投 ES（PR-S17-OUTB）。
//
// 设计要点：
//   - 携带完整 row 数据（ID + 元数据 + payload），避免 relay handler 二次查 PG
//   - JSON 序列化 → outbox.payload 列；Topic 版本号 .v1 防 schema 演进破坏老消息
//   - Topic 拼成常量字串（不依赖运行时字段；零值 ev.Topic() 也返同值）
type ResultBatchInsertedEvent struct {
	Rows []ResultEventRow `json:"rows"`
}

// ResultEventRow ScanResult 的 JSON 友好快照（与 domain.ScanResult 字段同形）。
type ResultEventRow struct {
	ID           string         `json:"id"`
	TenantID     string         `json:"tenant_id"`
	ProjectID    string         `json:"project_id"`
	TaskID       string         `json:"task_id"`
	AssignmentID string         `json:"assignment_id"`
	NodeID       string         `json:"node_id"`
	Kind         string         `json:"kind"`
	Data         map[string]any `json:"data"`
	CreatedAt    time.Time      `json:"created_at"`
}

// Topic 返事件总线 topic 字串。常量；与 zero value 也兼容。
func (ResultBatchInsertedEvent) Topic() string { return "scan.result.batch_inserted.v1" }

// ToScanResults 把 event row 还原为 *domain.ScanResult 切片，供 handler 投 ES。
func (e ResultBatchInsertedEvent) ToScanResults() []*domain.ScanResult {
	out := make([]*domain.ScanResult, 0, len(e.Rows))
	for i := range e.Rows {
		r := &e.Rows[i]
		out = append(out, &domain.ScanResult{
			ID:           r.ID,
			TenantID:     r.TenantID,
			ProjectID:    r.ProjectID,
			TaskID:       r.TaskID,
			AssignmentID: r.AssignmentID,
			NodeID:       r.NodeID,
			Kind:         domain.TaskKind(r.Kind),
			Data:         r.Data,
			CreatedAt:    r.CreatedAt,
		})
	}
	return out
}

// resultsToEvent 把 service 内部 *domain.ScanResult 切片打包成事件。
func resultsToEvent(rows []*domain.ScanResult) ResultBatchInsertedEvent {
	ev := ResultBatchInsertedEvent{Rows: make([]ResultEventRow, 0, len(rows))}
	for _, r := range rows {
		ev.Rows = append(ev.Rows, ResultEventRow{
			ID:           r.ID,
			TenantID:     r.TenantID,
			ProjectID:    r.ProjectID,
			TaskID:       r.TaskID,
			AssignmentID: r.AssignmentID,
			NodeID:       r.NodeID,
			Kind:         string(r.Kind),
			Data:         r.Data,
			CreatedAt:    r.CreatedAt,
		})
	}
	return ev
}
