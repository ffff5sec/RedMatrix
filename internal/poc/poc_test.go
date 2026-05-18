package poc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ffff5sec/RedMatrix/internal/errx"
)

// === Template / Validate ===

func TestLoadTemplateBytes_HappyPath(t *testing.T) {
	y := []byte(`
id: test-1
info:
  name: Test
  severity: low
requests:
  - method: GET
    path: /a
    matchers:
      - type: status
        status: [200]
`)
	tpl, err := LoadTemplateBytes(y)
	require.NoError(t, err)
	assert.Equal(t, "test-1", tpl.ID)
	assert.Equal(t, SeverityLow, tpl.Info.Severity)
}

func TestValidate_RejectsBadSeverity(t *testing.T) {
	tpl := &Template{
		ID: "x", Info: Info{Name: "n", Severity: "weird"},
		Requests: []Request{{Path: "/", Matchers: []Matcher{{Type: MatcherStatus, Status: []int{200}}}}},
	}
	err := tpl.ValidateForLoad()
	require.Error(t, err)
	code, _ := errx.GetCode(err)
	assert.Equal(t, errx.ErrInvalidInput, code)
}

func TestValidate_RequiresMatchers(t *testing.T) {
	tpl := &Template{
		ID: "x", Info: Info{Name: "n", Severity: SeverityLow},
		Requests: []Request{{Path: "/", Matchers: nil}},
	}
	require.Error(t, tpl.ValidateForLoad())
}

func TestValidate_StatusMatcherNeedsValues(t *testing.T) {
	tpl := &Template{
		ID: "x", Info: Info{Name: "n", Severity: SeverityLow},
		Requests: []Request{{Path: "/", Matchers: []Matcher{{Type: MatcherStatus}}}},
	}
	require.Error(t, tpl.ValidateForLoad())
}

// === LoadDir ===

func TestLoadDir_SkipsNonYAML(t *testing.T) {
	fsys := fstest.MapFS{
		"x/a.yaml": &fstest.MapFile{Data: []byte(`
id: a
info:
  name: A
  severity: low
requests: [{path: /, matchers: [{type: status, status: [200]}]}]
`)},
		"x/README.md": &fstest.MapFile{Data: []byte("ignore me")},
	}
	tpls, err := LoadDir(fsys, "x", nil)
	require.NoError(t, err)
	require.Len(t, tpls, 1)
	assert.Equal(t, "a", tpls[0].ID)
}

func TestLoadDir_DuplicateIDLastWinsAndReportsError(t *testing.T) {
	tplYAML := func(id string) []byte {
		return []byte("id: " + id + "\ninfo:\n  name: x\n  severity: low\nrequests:\n  - path: /\n    matchers:\n      - type: status\n        status: [200]\n")
	}
	fsys := fstest.MapFS{
		"a.yaml": &fstest.MapFile{Data: tplYAML("same")},
		"b.yaml": &fstest.MapFile{Data: tplYAML("same")},
	}
	errs := []error{}
	_, err := LoadDir(fsys, ".", func(_ string, e error) { errs = append(errs, e) })
	require.NoError(t, err)
	assert.Len(t, errs, 1, "重复 id 应触发一次 onError")
}

func TestLoadDir_InvalidTemplateReportedNotFatal(t *testing.T) {
	fsys := fstest.MapFS{
		"bad.yaml":  &fstest.MapFile{Data: []byte("invalid: yaml: ::")},
		"good.yaml": &fstest.MapFile{Data: []byte("id: g\ninfo: {name: g, severity: low}\nrequests: [{path: /, matchers: [{type: status, status: [200]}]}]\n")},
	}
	errs := []error{}
	tpls, err := LoadDir(fsys, ".", func(_ string, e error) { errs = append(errs, e) })
	require.NoError(t, err)
	require.Len(t, tpls, 1)
	assert.Equal(t, "g", tpls[0].ID)
	assert.NotEmpty(t, errs, "bad.yaml 应报错")
}

// === LoadDefault（内嵌）===

func TestLoadDefault_LoadsEmbeddedTemplates(t *testing.T) {
	tpls, err := LoadDefault()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(tpls), 14, "应加载 ≥ 14 个内嵌模板（PR-S72 扩展）")
	ids := map[string]bool{}
	for _, tp := range tpls {
		ids[tp.ID] = true
	}
	// 三类基线（PR-S69 内嵌）
	assert.True(t, ids["apache-server-status-exposed"])
	assert.True(t, ids["git-config-exposed"])
	assert.True(t, ids["phpinfo-page-exposed"])
	// PR-S72 扩展（部分）
	for _, expect := range []string{
		"env-file-exposed", "swagger-ui-exposed", "backup-sql-exposed",
		"jenkins-panel", "grafana-panel", "weblogic-console",
		"spring-actuator-exposed", "elasticsearch-no-auth", "prometheus-metrics-exposed",
		"tomcat-manager-probe",
	} {
		assert.True(t, ids[expect], "应含模板 %s", expect)
	}
}

// === Matcher unit ===

func TestMatch_StatusOnly(t *testing.T) {
	req := &Request{Matchers: []Matcher{{Type: MatcherStatus, Status: []int{200, 301}}}}
	assert.True(t, Match(req, &Response{Status: 200}))
	assert.True(t, Match(req, &Response{Status: 301}))
	assert.False(t, Match(req, &Response{Status: 404}))
}

func TestMatch_WordCaseInsensitive(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type: MatcherWord, Part: "body",
		Words: []string{"PHP Version"},
	}}}
	assert.True(t, Match(req, &Response{Body: "<h1>php version 8.2</h1>"}))
	assert.False(t, Match(req, &Response{Body: "nothing here"}))
}

func TestMatch_WordAndCondition(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type: MatcherWord, Part: "body",
		Words:     []string{"alpha", "beta"},
		Condition: "and",
	}}}
	assert.True(t, Match(req, &Response{Body: "alpha beta gamma"}))
	assert.False(t, Match(req, &Response{Body: "alpha only"}))
}

func TestMatch_Regex(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type:  MatcherRegex,
		Part:  "body",
		Regex: []string{`\[core\]`},
	}}}
	assert.True(t, Match(req, &Response{Body: "[core]\n\trepositoryformatversion = 0\n"}))
	assert.False(t, Match(req, &Response{Body: "no match"}))
}

func TestMatch_RegexInvalidPatternNoMatch(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type:  MatcherRegex,
		Regex: []string{`(unclosed`},
	}}}
	assert.False(t, Match(req, &Response{Body: "anything"}))
}

func TestMatch_DSL(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type: MatcherDSL,
		DSL: []string{
			`response.status == 200`,
			`response.body.contains("ok")`,
		},
		Condition: "and",
	}}}
	assert.True(t, Match(req, &Response{Status: 200, Body: "all is ok here"}))
	assert.False(t, Match(req, &Response{Status: 200, Body: "missing keyword"}))
	assert.False(t, Match(req, &Response{Status: 404, Body: "ok"}))
}

func TestMatch_MultipleMatchersAndCondition(t *testing.T) {
	req := &Request{
		MatchersCondition: "and",
		Matchers: []Matcher{
			{Type: MatcherStatus, Status: []int{200}},
			{Type: MatcherWord, Part: "body", Words: []string{"Apache"}},
		},
	}
	assert.True(t, Match(req, &Response{Status: 200, Body: "Apache Server Status"}))
	assert.False(t, Match(req, &Response{Status: 200, Body: "nope"}))
	assert.False(t, Match(req, &Response{Status: 500, Body: "Apache"}))
}

func TestMatch_MultipleMatchersOrCondition(t *testing.T) {
	req := &Request{
		MatchersCondition: "or",
		Matchers: []Matcher{
			{Type: MatcherStatus, Status: []int{200}},
			{Type: MatcherWord, Part: "body", Words: []string{"flag"}},
		},
	}
	assert.True(t, Match(req, &Response{Status: 200}))
	assert.True(t, Match(req, &Response{Status: 500, Body: "flag found"}))
	assert.False(t, Match(req, &Response{Status: 500, Body: "nope"}))
}

func TestMatch_NegativeMatcher(t *testing.T) {
	req := &Request{Matchers: []Matcher{{
		Type:     MatcherStatus,
		Status:   []int{404},
		Negative: true,
	}}}
	assert.True(t, Match(req, &Response{Status: 200}), "non-404 应命中（negative）")
	assert.False(t, Match(req, &Response{Status: 404}))
}

// === Runner（用 httptest 真起 HTTP server）===

func TestRunner_ExecuteSimpleGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/server-status" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Apache Server Status for localhost\nServer uptime: 5 days"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	runner := NewRunner(srv.Client())
	resp, err := runner.Execute(context.Background(), srv.URL, Request{Path: "/server-status"})
	require.NoError(t, err)
	assert.Equal(t, 200, resp.Status)
	assert.Contains(t, resp.Body, "Apache Server Status")
}

// === Engine end-to-end ===

func TestEngine_HitsServerStatusTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Apache Server Status\nServer uptime"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tpls, err := LoadDefault()
	require.NoError(t, err)

	eng := NewEngine(NewRunner(srv.Client()))
	findings := eng.Run(context.Background(), srv.URL, tpls)
	require.NotEmpty(t, findings)
	hit := findings[0]
	assert.Equal(t, "apache-server-status-exposed", hit.TemplateID)
	assert.Equal(t, SeverityLow, hit.Severity)
}

func TestEngine_NoMatchReturnsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tpls, _ := LoadDefault()
	eng := NewEngine(NewRunner(srv.Client()))
	findings := eng.Run(context.Background(), srv.URL, tpls)
	assert.Empty(t, findings)
}

func TestEngine_CtxCancelStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tpls, _ := LoadDefault()
	eng := NewEngine(NewRunner(srv.Client()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消
	findings := eng.Run(ctx, srv.URL, tpls)
	assert.Empty(t, findings)
}

// === PR-S72 端到端命中 ===

// TestEngine_HitsMultipleTemplates 模拟一个 server 多端点返各模板期望的特征，
// 验证 ≥6 个模板能被命中。
func TestEngine_HitsMultipleTemplates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("APP_KEY=abc\nDB_PASSWORD=s3cret\n"))
		case "/swagger-ui.html":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>Swagger UI loaded; swagger.json at /v2/api-docs</body></html>`))
		case "/backup.sql":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("-- MySQL dump 10.13  Distrib 8.0.32\n-- Host: localhost\nCREATE TABLE users(id INT);"))
		case "/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><title>Grafana</title><body>Welcome to Grafana</body></html>`))
		case "/actuator":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"_links":{"self":{"href":"/actuator/"},"health":{"href":"/actuator/health"}}}`))
		case "/actuator/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"UP"}`))
		case "/_cluster/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"cluster_name":"docker-cluster","status":"green","number_of_nodes":1}`))
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("# HELP http_requests_total The total number of HTTP requests.\n# TYPE http_requests_total counter\nhttp_requests_total 1\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tpls, err := LoadDefault()
	require.NoError(t, err)
	eng := NewEngine(NewRunner(srv.Client()))
	findings := eng.Run(context.Background(), srv.URL, tpls)
	require.GreaterOrEqual(t, len(findings), 6,
		"应至少命中 6 个模板（env/swagger/backup/grafana/actuator/elasticsearch/prometheus 中）")

	gotIDs := map[string]bool{}
	for _, f := range findings {
		gotIDs[f.TemplateID] = true
	}
	for _, want := range []string{
		"env-file-exposed",
		"swagger-ui-exposed",
		"backup-sql-exposed",
		"grafana-panel",
		"spring-actuator-exposed",
		"elasticsearch-no-auth",
		"prometheus-metrics-exposed",
	} {
		assert.True(t, gotIDs[want], "应命中 %s", want)
	}
}
