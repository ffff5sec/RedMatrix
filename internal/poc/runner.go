package poc

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// Response 抽出来的 HTTP 响应快照；matcher 读它而非原 *http.Response。
type Response struct {
	Status  int
	Body    string
	Headers map[string][]string
}

// Client 是 runner 的可注入 HTTP 客户端；测试用 httptest.Server。
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}

// Runner 单 template 执行器。
type Runner struct {
	client     Client
	maxBodyB   int64         // 响应 body 读取上限（防巨包）
	reqTimeout time.Duration // 单 request 超时；与 ctx deadline 取最严
}

// RunnerOption 函数式选项。
type RunnerOption func(*Runner)

// WithMaxBody 调响应读取上限；默认 1 MiB。
func WithMaxBody(b int64) RunnerOption { return func(r *Runner) { r.maxBodyB = b } }

// WithRequestTimeout 单请求超时；默认 15s。
func WithRequestTimeout(d time.Duration) RunnerOption {
	return func(r *Runner) { r.reqTimeout = d }
}

// NewRunner 构造；client = nil 时用默认 http.Client（含 InsecureSkipVerify
// —— POC 扫描场景下 self-signed cert 是常态）。
func NewRunner(client Client, opts ...RunnerOption) *Runner {
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // POC 场景允许
			},
		}
	}
	r := &Runner{
		client:     client,
		maxBodyB:   1 << 20, // 1 MiB
		reqTimeout: 15 * time.Second,
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Execute 跑单条 Request；返响应快照。
// baseURL 是 target（如 https://example.com:8443），request.Path 拼接其后。
func (r *Runner) Execute(ctx context.Context, baseURL string, req Request) (*Response, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errx.New(errx.ErrInvalidInput, "poc.runner: baseURL 为空")
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}
	fullURL := strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(req.Path, "/")

	reqCtx, cancel := context.WithTimeout(ctx, r.reqTimeout)
	defer cancel()

	body := strings.NewReader(req.Body)
	httpReq, err := http.NewRequestWithContext(reqCtx, method, fullURL, body)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInvalidInput, err, "poc.runner: new request")
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	// 默认 UA 避免被 WAF 直接拒
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", "RedMatrix-POC/1.0")
	}

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "poc.runner: http do")
	}
	defer resp.Body.Close() //nolint:errcheck // 只读关闭，无业务逻辑

	limited := io.LimitReader(resp.Body, r.maxBodyB)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, errx.Wrap(errx.ErrInternal, err, "poc.runner: read body")
	}
	return &Response{
		Status:  resp.StatusCode,
		Body:    string(bodyBytes),
		Headers: resp.Header,
	}, nil
}
