// Package export 提供资产 / 漏洞等数据的 HTTP 下载导出（PR-S63）。
//
// 设计：
//   - Format 接口抽象 CSV / JSON / XLSX 输出器；每个 resource exporter 只关心
//     列定义 + 行序列化，格式由 Format 决定
//   - Resource 接口让 assets / findings 等共享同一 HTTP 入口骨架
//   - 流式：分页拉数据，立即 flush 到 ResponseWriter；avoid 把全量装内存
package export

import (
	"context"
	"io"
)

// Row 单条记录的字符串化字段集合；列顺序由 Columns 决定。
type Row []string

// Format 一种输出格式（csv / json）。
type Format interface {
	// ContentType HTTP Content-Type 头。
	ContentType() string
	// Extension 文件名扩展，例如 "csv"、"json"。
	Extension() string
	// WriteHeader 写表头；JSON 实现可空操作。
	WriteHeader(w io.Writer, cols []string) error
	// WriteRow 写一行。
	WriteRow(w io.Writer, cols []string, row Row) error
	// Close 收尾（如 JSON 关闭 array）。
	Close(w io.Writer) error
}

// Resource 一种可导出资源（assets / findings）。
//
// 实现负责按 RBAC scope 拉取记录，逐页推到 emit 回调。emit 中遇到 ctx.Done 即停。
type Resource interface {
	// Name 资源名，用作文件名前缀，例如 "assets"、"findings"。
	Name() string
	// Columns 列名（写到 CSV 表头 / JSON 字段 key）。
	Columns() []string
	// Stream 逐页拉数据；scope 是 caller 注入的 RBAC 边界。
	// emit(row) 返 error 时停止；调用方负责把行写到 Format。
	Stream(ctx context.Context, scope Scope, emit func(Row) error) error
}

// Scope 单次导出的 RBAC 边界 + 业务过滤。
type Scope struct {
	// TenantID 限定的 tenant；SA / PlatformAuditor 可空（不限）。
	TenantID string
	// ProjectIDs PA 路径可见的项目集合；nil = 不限；空切片 = 0 项目（短路返空）。
	ProjectIDs []string
	// Query 业务过滤；resource 自己解析需要的字段。
	Query map[string][]string
}
