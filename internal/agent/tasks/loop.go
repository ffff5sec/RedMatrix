// Package tasks 是 Agent 的任务执行循环（PR-S3）。
//
// 行为：
//   - 每 PullInterval（默认 30s）调 NodeAgentService.PullTasks
//   - 每条 AssignedTask 启 1 个 goroutine：ReportTaskProgress(running)
//     → 模拟 ExecDuration（默认 2s）→ ReportTaskProgress(completed/failed)
//   - 失败概率由 FailureRate 控制（仅演示用；MVP 0%）
//   - ctx 取消时停拉，已起的 task goroutine 跑完即退
package tasks

import (
	"context"
	mathrand "math/rand"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"

	tenancyv1 "github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1"
	"github.com/ffff5sec/RedMatrix/gen/proto/redmatrix/tenancy/v1/tenancyv1connect"
)

const (
	DefaultPullInterval = 30 * time.Second
	DefaultExecDuration = 2 * time.Second
)

// Logger 复用 heartbeat 包的简化签名。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Info(string, ...any) {}
func (noopLogger) Warn(string, ...any) {}

// Loop 跑任务拉取 + mock 执行。
type Loop struct {
	Client       tenancyv1connect.NodeAgentServiceClient
	PullInterval time.Duration
	ExecDuration time.Duration
	FailureRate  float64 // [0, 1]；0 = 永不失败
	Logger       Logger
	Rand         *mathrand.Rand
}

// Run 阻塞直到 ctx 取消；已派发 goroutine 等其完成。
func (l *Loop) Run(ctx context.Context) error {
	if l == nil || l.Client == nil {
		return nil
	}
	logger := l.Logger
	if logger == nil {
		logger = noopLogger{}
	}
	pullEvery := l.PullInterval
	if pullEvery <= 0 {
		pullEvery = DefaultPullInterval
	}
	rng := l.Rand
	if rng == nil {
		rng = mathrand.New(mathrand.NewSource(time.Now().UnixNano())) //nolint:gosec // mock 用，无安全语义
	}

	var wg sync.WaitGroup
	defer wg.Wait()

	// 首次立即拉一次
	l.pullAndDispatch(ctx, &wg, logger, rng)

	t := time.NewTicker(pullEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			l.pullAndDispatch(ctx, &wg, logger, rng)
		}
	}
}

func (l *Loop) pullAndDispatch(
	ctx context.Context,
	wg *sync.WaitGroup,
	logger Logger,
	rng *mathrand.Rand,
) {
	res, err := l.Client.PullTasks(ctx, connect.NewRequest(&tenancyv1.PullTasksRequest{}))
	if err != nil {
		logger.Warn("tasks: pull failed", "err", err.Error())
		return
	}
	if res.Msg == nil || len(res.Msg.GetTasks()) == 0 {
		return
	}
	logger.Info("tasks: pulled", "count", len(res.Msg.GetTasks()))
	for _, t := range res.Msg.GetTasks() {
		wg.Add(1)
		go func(at *tenancyv1.AssignedTask) {
			defer wg.Done()
			l.execMock(ctx, at, logger, rng)
		}(t)
	}
}

func (l *Loop) execMock(
	ctx context.Context,
	at *tenancyv1.AssignedTask,
	logger Logger,
	rng *mathrand.Rand,
) {
	dur := l.ExecDuration
	if dur <= 0 {
		dur = DefaultExecDuration
	}

	// 1. running
	if err := l.report(ctx, at.GetAssignmentId(), "running", ""); err != nil {
		logger.Warn("tasks: report running failed",
			"assignment_id", at.GetAssignmentId(), "err", err.Error())
		return
	}
	logger.Info("tasks: running",
		"assignment_id", at.GetAssignmentId(),
		"kind", at.GetKind(),
		"target", at.GetTarget(),
	)

	// 2. mock work（中间允许 ctx cancel 提前退出）
	select {
	case <-ctx.Done():
		return
	case <-time.After(dur):
	}

	// 3. PR-S5：mock 出一份结果（按 task.kind 给出固定 fixture）
	failed := false
	if l.FailureRate > 0 && rng.Float64() < l.FailureRate {
		failed = true
	}
	if !failed {
		results := mockResults(at)
		if len(results) > 0 {
			if err := l.reportResults(ctx, at.GetAssignmentId(), results); err != nil {
				logger.Warn("tasks: report results failed",
					"assignment_id", at.GetAssignmentId(), "err", err.Error())
				// 结果上报失败仍继续推 completed（避免无限重试）
			}
		}
	}

	// 4. completed / failed
	status := "completed"
	errMsg := ""
	if failed {
		status = "failed"
		errMsg = "mock failure (FailureRate triggered)"
	}
	if err := l.report(ctx, at.GetAssignmentId(), status, errMsg); err != nil {
		logger.Warn("tasks: report final failed",
			"assignment_id", at.GetAssignmentId(),
			"intended_status", status,
			"err", err.Error())
		return
	}
	logger.Info("tasks: done",
		"assignment_id", at.GetAssignmentId(),
		"status", status,
	)
}

// mockResults 按 task.kind 出固定假数据。后续真插件接入时本函数被替换为
// 调用对应 plugin 的入口。
func mockResults(at *tenancyv1.AssignedTask) []map[string]any {
	target := at.GetTarget()
	switch at.GetKind() {
	case "port_scan":
		return []map[string]any{
			{"host": target, "port": 22, "service": "ssh", "banner": "OpenSSH 8.2 (mock)"},
			{"host": target, "port": 80, "service": "http", "banner": "nginx/1.18 (mock)"},
		}
	case "web_crawl":
		return []map[string]any{
			{"url": target, "status": 200, "title": "Example Domain (mock)"},
		}
	case "subdomain":
		return []map[string]any{
			{"name": "api." + target, "ip": "192.0.2.1"},
			{"name": "www." + target, "ip": "192.0.2.2"},
		}
	case "fingerprint":
		return []map[string]any{
			{"target": target, "tech": []string{"nginx", "Vue.js"}},
		}
	}
	return nil
}

func (l *Loop) reportResults(ctx context.Context, assignmentID string, items []map[string]any) error {
	pbItems := make([]*structpb.Struct, 0, len(items))
	for _, it := range items {
		s, err := structpb.NewStruct(it)
		if err != nil {
			return err
		}
		pbItems = append(pbItems, s)
	}
	_, err := l.Client.ReportTaskResults(ctx, connect.NewRequest(&tenancyv1.ReportTaskResultsRequest{
		AssignmentId: assignmentID,
		Items:        pbItems,
	}))
	return err
}

func (l *Loop) report(ctx context.Context, assignmentID, status, errMsg string) error {
	_, err := l.Client.ReportTaskProgress(ctx, connect.NewRequest(&tenancyv1.ReportTaskProgressRequest{
		AssignmentId: assignmentID,
		Status:       status,
		Error:        errMsg,
	}))
	return err
}
