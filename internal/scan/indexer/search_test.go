package indexer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/ffff5sec/RedMatrix/internal/storage/es"
)

// searchStub 让测试断言请求 body 形状 + 自定义 ES 响应。
type searchStub struct {
	lastBody string
	respBody string
	status   int
}

func newSearchStub(t *testing.T, resp string, status int) (*Indexer, *searchStub, *httptest.Server) {
	t.Helper()
	stub := &searchStub{respBody: resp, status: status}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		stub.lastBody = string(body)
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		if stub.status > 0 {
			w.WriteHeader(stub.status)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_, _ = w.Write([]byte(stub.respBody))
	}))
	raw, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{srv.URL},
	})
	if err != nil {
		srv.Close()
		t.Fatalf("client: %v", err)
	}
	idx, err := New(&es.Client{Client: raw})
	if err != nil {
		srv.Close()
		t.Fatalf("New: %v", err)
	}
	return idx, stub, srv
}

const validSearchResp = `{
  "hits": {
    "total": {"value": 2},
    "hits": [
      {"_source": {"id":"r1","tenant_id":"T","project_id":"P","task_id":"task-1","assignment_id":"a-1","node_id":"node-x","kind":"port_scan","data":{"host":"1.2.3.4","port":22},"created_at":"2026-05-09T00:00:00Z"}},
      {"_source": {"id":"r2","tenant_id":"T","project_id":"P","task_id":"task-1","assignment_id":"a-1","node_id":"node-x","kind":"port_scan","data":{"host":"1.2.3.4","port":80},"created_at":"2026-05-09T00:00:01Z"}}
    ]
  },
  "aggregations": {
    "by_kind": {"buckets":[{"key":"port_scan","doc_count":2}]},
    "by_node": {"buckets":[{"key":"node-x","doc_count":2}]}
  }
}`

func TestSearch_QueryShape_AllFilters(t *testing.T) {
	idx, stub, srv := newSearchStub(t, validSearchResp, 0)
	defer srv.Close()

	from := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 5, 9, 23, 0, 0, 0, time.UTC)
	_, err := idx.Search(context.Background(), SearchQuery{
		Keyword:    "nginx",
		TenantID:   "tenant-1",
		ProjectIDs: []string{"p-1", "p-2"},
		NodeID:     "node-x",
		TaskID:     "task-1",
		Kind:       "port_scan",
		TimeFrom:   &from,
		TimeTo:     &to,
		Page:       2,
		PageSize:   25,
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(stub.lastBody), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["from"].(float64) != 25 {
		t.Errorf("from: want 25, got %v", body["from"])
	}
	if body["size"].(float64) != 25 {
		t.Errorf("size: want 25, got %v", body["size"])
	}
	q, _ := body["query"].(map[string]any)
	bc, _ := q["bool"].(map[string]any)
	if bc == nil {
		t.Fatalf("query.bool missing: %s", stub.lastBody)
	}
	must, _ := bc["must"].([]any)
	if len(must) != 1 {
		t.Errorf("must clause count: %d", len(must))
	}
	filters, _ := bc["filter"].([]any)
	// tenant_id, project_ids(terms), node_id, task_id, kind, range = 6
	if len(filters) != 6 {
		t.Errorf("filter count: want 6, got %d (body=%s)", len(filters), stub.lastBody)
	}
	// kind agg + node agg
	aggs, _ := body["aggs"].(map[string]any)
	if _, ok := aggs["by_kind"]; !ok {
		t.Error("aggs.by_kind missing")
	}
	if _, ok := aggs["by_node"]; !ok {
		t.Error("aggs.by_node missing")
	}
}

func TestSearch_ParseResponse(t *testing.T) {
	idx, _, srv := newSearchStub(t, validSearchResp, 0)
	defer srv.Close()

	page, err := idx.Search(context.Background(), SearchQuery{Page: 1, PageSize: 50})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if page.Total != 2 {
		t.Errorf("total: %d", page.Total)
	}
	if len(page.Items) != 2 {
		t.Fatalf("items: %d", len(page.Items))
	}
	if page.Items[0].ID != "r1" || page.Items[1].ID != "r2" {
		t.Errorf("ids: %s, %s", page.Items[0].ID, page.Items[1].ID)
	}
	if page.Items[0].TenantID != "T" || page.Items[0].ProjectID != "P" {
		t.Errorf("tenant/project: %s / %s", page.Items[0].TenantID, page.Items[0].ProjectID)
	}
	// data 解出来
	if page.Items[0].Data["host"] != "1.2.3.4" {
		t.Errorf("data.host: %v", page.Items[0].Data["host"])
	}
	// facets
	if len(page.Facets) != 2 {
		t.Fatalf("facets: %d", len(page.Facets))
	}
	for _, f := range page.Facets {
		if f.Field == "kind" && (len(f.Buckets) != 1 || f.Buckets[0].Key != "port_scan" || f.Buckets[0].Count != 2) {
			t.Errorf("kind facet: %+v", f)
		}
	}
}

func TestSearch_EmptyFilters_MatchAll(t *testing.T) {
	idx, stub, srv := newSearchStub(t, validSearchResp, 0)
	defer srv.Close()

	_, err := idx.Search(context.Background(), SearchQuery{})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if !strings.Contains(stub.lastBody, "match_all") {
		t.Errorf("expect match_all in body: %s", stub.lastBody)
	}
}

func TestSearch_404_ReturnsEmpty(t *testing.T) {
	idx, _, srv := newSearchStub(t, `{"error":"index not found"}`, http.StatusNotFound)
	defer srv.Close()

	page, err := idx.Search(context.Background(), SearchQuery{TenantID: "t"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if page == nil || len(page.Items) != 0 || page.Total != 0 {
		t.Errorf("want empty page on 404, got %+v", page)
	}
}

func TestSearch_DeepPagination_Rejected(t *testing.T) {
	idx, _, srv := newSearchStub(t, validSearchResp, 0)
	defer srv.Close()

	// page=201 * size=50 = 10050 > 10000
	_, err := idx.Search(context.Background(), SearchQuery{Page: 201, PageSize: 50})
	if err == nil {
		t.Error("expect deep pagination rejected")
	}
}

func TestSearch_PageSizeCap(t *testing.T) {
	idx, stub, srv := newSearchStub(t, validSearchResp, 0)
	defer srv.Close()

	_, err := idx.Search(context.Background(), SearchQuery{PageSize: 5000})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(stub.lastBody), &body)
	if body["size"].(float64) != float64(maxSearchSize) {
		t.Errorf("size cap: want %d, got %v", maxSearchSize, body["size"])
	}
}
