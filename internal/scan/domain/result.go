package domain

import (
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// ScanResult 扫描结果领域实体（PR-S5）。
//
// data 是 schema-less JSONB；按 kind 渲染：
//   - port_scan:    {"host": "1.2.3.4", "port": 22, "service": "ssh", "banner": "..."}
//   - web_crawl:    {"url": "https://x/y", "status": 200, "title": "..."}
//   - subdomain:    {"name": "api.example.com", "ip": "1.2.3.4"}
//   - fingerprint:  {"target": "https://x", "tech": ["nginx", "vue"]}
type ScanResult struct {
	ID           string
	TaskID       string
	AssignmentID string
	NodeID       string
	Kind         TaskKind
	Data         map[string]any
	CreatedAt    time.Time
}

// ValidateForCreate INSERT 前校验。
func (r *ScanResult) ValidateForCreate() error {
	if r == nil {
		return errx.New(errx.ErrInvalidInput, "result is nil")
	}
	if strings.TrimSpace(r.TaskID) == "" {
		return errx.New(errx.ErrInvalidInput, "result.task_id 不能为空")
	}
	if strings.TrimSpace(r.AssignmentID) == "" {
		return errx.New(errx.ErrInvalidInput, "result.assignment_id 不能为空")
	}
	if strings.TrimSpace(r.NodeID) == "" {
		return errx.New(errx.ErrInvalidInput, "result.node_id 不能为空")
	}
	if !r.Kind.Valid() {
		return errx.New(errx.ErrTaskInvalidState, "result.kind 不合法").
			WithFields("got", string(r.Kind))
	}
	if r.Data == nil {
		r.Data = map[string]any{}
	}
	return nil
}
