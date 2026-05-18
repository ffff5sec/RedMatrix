package poc

import (
	"context"
	"errors"
)

// Finding 单条命中。
type Finding struct {
	TemplateID string
	Name       string
	Severity   Severity
	Tags       []string
	Reference  []string
	// MatchedAt 哪一条 request（多 request 模板用）。
	MatchedRequestIdx int
}

// Engine 多模板执行器。零值不可用，用 NewEngine。
type Engine struct {
	runner *Runner
}

// NewEngine 构造；runner = nil 时用默认。
func NewEngine(runner *Runner) *Engine {
	if runner == nil {
		runner = NewRunner(nil)
	}
	return &Engine{runner: runner}
}

// Run 对单个 target 跑全部 templates；返命中。
//
// 单个 template 跑出错（HTTP 超时 / 解析错）静默跳过，不阻断其他。
// ctx 取消立即返已有结果（不等剩余 templates）。
func (e *Engine) Run(ctx context.Context, target string, templates []*Template) []*Finding {
	if e == nil || len(templates) == 0 || target == "" {
		return nil
	}
	out := []*Finding{}
	for _, t := range templates {
		if ctx.Err() != nil {
			return out
		}
		if t == nil {
			continue
		}
		f := e.runOne(ctx, target, t)
		if f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) runOne(ctx context.Context, target string, t *Template) *Finding {
	for i := range t.Requests {
		req := &t.Requests[i]
		resp, err := e.runner.Execute(ctx, target, *req)
		if err != nil {
			// 网络错 / ctx 取消 — 跳过整个 template（多请求模板里某条挂了无法继续）
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			continue
		}
		if Match(req, resp) {
			return &Finding{
				TemplateID:        t.ID,
				Name:              t.Info.Name,
				Severity:          t.Info.Severity,
				Tags:              t.Info.Tags,
				Reference:         t.Info.Reference,
				MatchedRequestIdx: i,
			}
		}
	}
	return nil
}
