// Package tasks 是 Agent 的任务执行循环（PR-S3）。
//
// 行为：
//   - 每 PullInterval（默认 30s）调 NodeAgentService.PullTasks
//   - 每条 AssignedTask 启 1 个 goroutine：ReportTaskProgress(running)
//     → 调 Plugin.Run（PR-S9）→ ReportTaskResults → ReportTaskProgress
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
	"github.com/ffff5sec/RedMatrix/internal/agent/plugin"
)

const (
	DefaultPullInterval = 30 * time.Second
	DefaultExecDuration = 2 * time.Second
	// DefaultPluginTimeout 单条任务执行总超时；防止单个工具卡死把 agent 占满。
	DefaultPluginTimeout = 10 * time.Minute
)

// Logger 复用 heartbeat 包的简化签名。
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

type noopLogger struct{}

func (noopLogger) Info(string, ...any) {}
func (noopLogger) Warn(string, ...any) {}

// Loop 跑任务拉取 + 插件执行。
type Loop struct {
	Client       tenancyv1connect.NodeAgentServiceClient
	PullInterval time.Duration
	// ExecDuration 仅 mock fallback 路径生效（保持 PR-S3 demo 节奏）；
	// 真插件路径用 PluginTimeout 控总超时。
	ExecDuration time.Duration
	// PluginTimeout 单条任务执行总超时；0 = DefaultPluginTimeout
	PluginTimeout time.Duration
	FailureRate   float64 // [0, 1]；0 = 永不失败
	Logger        Logger
	Rand          *mathrand.Rand
	// Plugins kind → Plugin 路由表；nil 时按 mock 全套自动注册（兼容旧测试 / dev）
	Plugins *plugin.Registry
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
	// PR-S9：Plugins 未注入时回落 mock 全套（保持 PR-S3 行为兼容）
	if l.Plugins == nil {
		l.Plugins = plugin.NewRegistry()
		plugin.RegisterAllMock(l.Plugins)
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
			l.execTask(ctx, at, logger, rng)
		}(t)
	}
}

// execTask 执行单条任务（PR-S9 取代 execMock）：
//
//  1. report running
//  2. 取 plugin（按 kind）；mock plugin 走 ExecDuration 节奏，真插件用 PluginTimeout 控总耗时
//  3. report results
//  4. report completed / failed
func (l *Loop) execTask(
	ctx context.Context,
	at *tenancyv1.AssignedTask,
	logger Logger,
	rng *mathrand.Rand,
) {
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

	// 2. 选 plugin
	p := l.Plugins.Get(at.GetKind())
	if p == nil {
		// 完全找不到（不应发生：mock 已自动注册）→ 标 failed
		_ = l.report(ctx, at.GetAssignmentId(), "failed",
			"no plugin registered for kind="+at.GetKind())
		return
	}

	// 3. FailureRate 注入（仅 demo / 测试）
	failed := false
	if l.FailureRate > 0 && rng.Float64() < l.FailureRate {
		failed = true
	}

	var results []map[string]any
	var execErr error
	if !failed {
		// 保留 PR-S3 demo 节奏：mock 路径才 sleep ExecDuration
		if isMockPlugin(p) {
			dur := l.ExecDuration
			if dur <= 0 {
				dur = DefaultExecDuration
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(dur):
			}
		}
		// 总超时：真插件 ≤ PluginTimeout（防卡死）
		timeout := l.PluginTimeout
		if timeout <= 0 {
			timeout = DefaultPluginTimeout
		}
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		// MVP：settings 暂未在 AssignedTask 上承载（后续扩 proto）。
		results, execErr = p.Run(runCtx, at.GetTarget(), at.GetTargetKind(), nil)
		cancel()
		if execErr != nil {
			failed = true
			logger.Warn("tasks: plugin run failed",
				"assignment_id", at.GetAssignmentId(),
				"kind", at.GetKind(),
				"err", execErr.Error())
		}
	}

	// 4. report results
	if !failed && len(results) > 0 {
		if err := l.reportResults(ctx, at.GetAssignmentId(), results); err != nil {
			logger.Warn("tasks: report results failed",
				"assignment_id", at.GetAssignmentId(), "err", err.Error())
			// 仍走 completed，避免无限重试
		}
	}

	// 5. completed / failed
	status := "completed"
	errMsg := ""
	if failed {
		status = "failed"
		if execErr != nil {
			errMsg = "plugin error: " + execErr.Error()
		} else {
			errMsg = "mock failure (FailureRate triggered)"
		}
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
		"result_count", len(results),
	)
}

// isMockPlugin 判定是否 mock；mock 才走 ExecDuration 节奏。
func isMockPlugin(p plugin.Plugin) bool {
	if p == nil {
		return false
	}
	type identifiable interface{ IsMock() bool }
	if m, ok := p.(identifiable); ok {
		return m.IsMock()
	}
	return false
}

// MaxResultsPerReport 单条 task 上报的最大结果数（PR-S13 整合 e2e 加固）。
//
// 真插件偶现上千行（subfinder example.com 22k+），单次 ReportTaskResults
// 包过大触发 connect stream INTERNAL_ERROR；MVP 直接截断 + 日志告知。
// 后续可改批量分页上报或改 server 端流式接口。
const MaxResultsPerReport = 1000

// reportBatchSize 单次 RPC 包上报多少条；分批降低单包体积。
const reportBatchSize = 200

func (l *Loop) reportResults(ctx context.Context, assignmentID string, items []map[string]any) error {
	if len(items) > MaxResultsPerReport {
		items = items[:MaxResultsPerReport]
	}
	for start := 0; start < len(items); start += reportBatchSize {
		end := start + reportBatchSize
		if end > len(items) {
			end = len(items)
		}
		pbItems := make([]*structpb.Struct, 0, end-start)
		for _, it := range items[start:end] {
			s, err := structpb.NewStruct(sanitizeForStruct(it))
			if err != nil {
				return err
			}
			pbItems = append(pbItems, s)
		}
		if _, err := l.Client.ReportTaskResults(ctx, connect.NewRequest(&tenancyv1.ReportTaskResultsRequest{
			AssignmentId: assignmentID,
			Items:        pbItems,
		})); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeForStruct 把任意 map 转成 structpb.NewStruct 可接受的形式：
//
//   - []string / []int / 其它 typed slice → []any（structpb 仅接受 []any）
//   - 嵌套 map[string]any → 递归
//   - 其它原值不动（structpb 处理得了）
func sanitizeForStruct(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = sanitizeValue(v)
	}
	return out
}

func sanitizeValue(v any) any {
	switch x := v.(type) {
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = s
		}
		return out
	case []int:
		out := make([]any, len(x))
		for i, n := range x {
			out[i] = float64(n) // structpb 数值统一 double
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = sanitizeValue(e)
		}
		return out
	case map[string]any:
		return sanitizeForStruct(x)
	default:
		return v
	}
}

func (l *Loop) report(ctx context.Context, assignmentID, status, errMsg string) error {
	_, err := l.Client.ReportTaskProgress(ctx, connect.NewRequest(&tenancyv1.ReportTaskProgressRequest{
		AssignmentId: assignmentID,
		Status:       status,
		Error:        errMsg,
	}))
	return err
}
