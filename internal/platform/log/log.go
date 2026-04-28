// Package log 是 RedMatrix 后端日志门面，包装 slog 提供：
//
//   - 标准化 attr 结构（与 docs/LLD/03-error-catalog.md §6 字段对齐）
//   - ctx-aware：从 ctx 自动注入 request_id / user_id / tenant_id / project_id / role
//   - LogError：自动解构 *errx.DomainError 为 code / message / cause / fields 结构
//
// 用法（与 docs/LLD/00-conventions.md §2.6 示例一致）：
//
//	log.Default().WithCtx(ctx).Info("asset upserted",
//	    "asset_id", id,
//	    "is_new", isNew,
//	    "duration_ms", elapsed.Milliseconds())
//
//	log.Default().LogError(ctx, "request failed", err)
//
// Level 映射：trace=-8 / debug=-4 / info=0 / warn=4 / error=8（slog 标准）。
package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"github.com/ffff5sec/RedMatrix/internal/errx"
	"github.com/ffff5sec/RedMatrix/internal/platform/ctxmeta"
)

// LevelTrace 是 slog.LevelDebug 之下的细粒度级别。
const LevelTrace = slog.Level(-8)

// Config 日志门面配置（与 internal/config.LogConfig 对应）。
type Config struct {
	// Level: trace | debug | info | warn | error。默认 info。
	Level string

	// Format: json | text。默认 json（生产 + Loki）。
	Format string

	// Output 目标 writer。默认 os.Stdout。测试场景注入 bytes.Buffer。
	Output io.Writer

	// AddSource 是否注入调用方 file:line（开发模式建议开；生产关）。默认 false。
	AddSource bool
}

// Logger 是 slog.Logger 的薄包装。零值不可用；必须用 New 构造。
type Logger struct {
	inner *slog.Logger
}

// New 构造 Logger。Level / Format 取值非法时返回 BOOTSTRAP_CONFIG_INVALID。
func New(cfg Config) (*Logger, error) {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	out := cfg.Output
	if out == nil {
		out = os.Stdout
	}
	hopts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
	}

	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "json":
		handler = slog.NewJSONHandler(out, hopts)
	case "text":
		handler = slog.NewTextHandler(out, hopts)
	default:
		return nil, errx.New(errx.ErrBootstrapConfigInvalid,
			"LOG_FORMAT 非法（json | text）").WithFields("got", cfg.Format)
	}
	return &Logger{inner: slog.New(handler)}, nil
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return slog.LevelInfo, nil
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, errx.New(errx.ErrBootstrapConfigInvalid,
		"LOG_LEVEL 非法").WithFields("got", s)
}

// === 默认 logger（package-level） ===

var defaultLogger atomic.Pointer[Logger]

func init() {
	// fallback：未 SetDefault 时也能用（写 stdout，info 级，json）。
	l, _ := New(Config{}) //nolint:errcheck // 默认配置不会失败
	defaultLogger.Store(l)
}

// Default 返回包级默认 logger。永远非 nil。
func Default() *Logger {
	return defaultLogger.Load()
}

// SetDefault 替换包级默认 logger（cmd/server 启动时调用一次）。
func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultLogger.Store(l)
}

// === 派生 ===

// With 返回一个新 Logger，附带固定 attrs。
func (l *Logger) With(args ...any) *Logger {
	if l == nil {
		return nil
	}
	return &Logger{inner: l.inner.With(args...)}
}

// WithCtx 从 ctx 提取 request_id / user_id / tenant_id / project_id / role 后
// 返回新 Logger。无任何 ctx 元数据时返回原 logger（避免分配）。
func (l *Logger) WithCtx(ctx context.Context) *Logger {
	if l == nil || ctx == nil {
		return l
	}
	attrs := ctxmeta.Attrs(ctx)
	if len(attrs) == 0 {
		return l
	}
	return &Logger{inner: l.inner.With(attrs...)}
}

// === 标准 log 方法 ===

// Trace 输出 trace 级日志（slog 标准之下，仅自定义 level）。
func (l *Logger) Trace(msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Log(context.Background(), LevelTrace, msg, args...)
}

func (l *Logger) Debug(msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Debug(msg, args...)
}

func (l *Logger) Info(msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Info(msg, args...)
}

func (l *Logger) Warn(msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Warn(msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	if l == nil {
		return
	}
	l.inner.Error(msg, args...)
}

// === 错误日志（DomainError-aware） ===

// LogError 把 err 解构后以 ERROR 级输出。
//
// err 是 *errx.DomainError（或链中含有）时，会自动展开为：
//   - code      = DomainError.Code
//   - message   = DomainError.Message
//   - cause     = DomainError.Cause.Error()（如有）
//   - fields    = DomainError.Fields（嵌套 group）
//
// 否则只输出 "error" 字段。ctx 元数据始终注入。
//
// 与 docs/LLD/03-error-catalog.md §6 示例 1:1 对齐。
func (l *Logger) LogError(ctx context.Context, msg string, err error, args ...any) {
	if l == nil || err == nil {
		return
	}
	logger := l.WithCtx(ctx)
	allArgs := buildErrorArgs(err)
	allArgs = append(allArgs, args...)
	logger.inner.Error(msg, allArgs...)
}

// buildErrorArgs 从 err 构造 slog attrs。
func buildErrorArgs(err error) []any {
	var de *errx.DomainError
	if !errors.As(err, &de) {
		return []any{"error", err.Error()}
	}
	args := []any{
		"code", string(de.Code),
		"message", de.Message,
	}
	if de.Cause != nil {
		args = append(args, "cause", de.Cause.Error())
	}
	if len(de.Fields) > 0 {
		args = append(args, slog.Group("fields", fieldAttrs(de.Fields)...))
	}
	return args
}

func fieldAttrs(fields map[string]any) []any {
	out := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		out = append(out, k, valueOf(v))
	}
	return out
}

// valueOf 把任意类型转为 slog 友好值。slog 自带支持 string/int/bool/float/error/Duration/Time。
// 其余走 fmt.Sprintf。
func valueOf(v any) any {
	switch v.(type) {
	case string, int, int64, int32, uint, uint64, uint32, bool, float64, float32, error:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
