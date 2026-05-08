package indexer

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"

	"github.com/ffff5sec/RedMatrix/internal/scan/domain"
	"github.com/ffff5sec/RedMatrix/internal/storage/es"
)

// stubES 把 httptest.Server 包成 *es.Client，让 Indexer 可直接打到 fake 后端。
type stubES struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func newStubClient(t *testing.T) (*es.Client, *stubES, *httptest.Server) {
	t.Helper()
	stub := &stubES{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		stub.mu.Lock()
		stub.requests = append(stub.requests, r)
		stub.bodies = append(stub.bodies, string(body))
		stub.mu.Unlock()
		// 模拟 ES 8.x 行为：HEAD / 写头部带 X-Elastic-Product
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		switch {
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/_index_template/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"acknowledged":true}`))
		case strings.HasSuffix(r.URL.Path, "/_bulk"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"took":1,"errors":false,"items":[]}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))

	raw, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{srv.URL},
	})
	if err != nil {
		srv.Close()
		t.Fatalf("new client: %v", err)
	}
	return &es.Client{Client: raw}, stub, srv
}

func TestIndexer_EnsureTemplate(t *testing.T) {
	client, stub, srv := newStubClient(t)
	defer srv.Close()

	idx, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := idx.EnsureTemplate(context.Background()); err != nil {
		t.Fatalf("EnsureTemplate: %v", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("want 1 request, got %d", len(stub.requests))
	}
	r := stub.requests[0]
	if r.Method != http.MethodPut {
		t.Errorf("method: want PUT, got %s", r.Method)
	}
	if !strings.HasSuffix(r.URL.Path, "/scan-results-template") {
		t.Errorf("path: %s", r.URL.Path)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(stub.bodies[0]), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	patterns, _ := body["index_patterns"].([]any)
	if len(patterns) == 0 || !strings.HasPrefix(patterns[0].(string), "scan-results") {
		t.Errorf("index_patterns: %v", body["index_patterns"])
	}
}

func TestIndexer_Index_BulkBody(t *testing.T) {
	client, stub, srv := newStubClient(t)
	defer srv.Close()

	idx, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	items := []*domain.ScanResult{
		{
			ID: "id-1", TaskID: "task-a", AssignmentID: "asn-a", NodeID: "node-x",
			Kind:      "port_scan",
			Data:      map[string]any{"host": "1.2.3.4", "port": float64(22)},
			CreatedAt: now,
		},
		{
			ID: "id-2", TaskID: "task-a", AssignmentID: "asn-a", NodeID: "node-x",
			Kind:      "port_scan",
			Data:      map[string]any{"host": "1.2.3.4", "port": float64(80)},
			CreatedAt: now,
		},
	}
	if err := idx.Index(context.Background(), items); err != nil {
		t.Fatalf("Index: %v", err)
	}
	if len(stub.requests) != 1 {
		t.Fatalf("want 1 bulk request, got %d", len(stub.requests))
	}
	if !strings.HasSuffix(stub.requests[0].URL.Path, "/_bulk") {
		t.Errorf("path not _bulk: %s", stub.requests[0].URL.Path)
	}
	// bulk body 是 NDJSON：4 行（meta / doc 交替 ×2）+ 末尾换行
	lines := strings.Split(strings.TrimRight(stub.bodies[0], "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("want 4 NDJSON lines, got %d: %q", len(lines), stub.bodies[0])
	}
	// 第 1 行 = meta with _id=id-1
	var meta1 map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &meta1); err != nil {
		t.Fatalf("decode meta1: %v", err)
	}
	idxOp, _ := meta1["index"].(map[string]any)
	if idxOp["_id"] != "id-1" {
		t.Errorf("meta1._id: want id-1, got %v", idxOp["_id"])
	}
	// 第 2 行 = doc1
	var doc1 map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &doc1); err != nil {
		t.Fatalf("decode doc1: %v", err)
	}
	if doc1["task_id"] != "task-a" {
		t.Errorf("doc1.task_id: want task-a, got %v", doc1["task_id"])
	}
	if doc1["kind"] != "port_scan" {
		t.Errorf("doc1.kind: %v", doc1["kind"])
	}
	if doc1["created_at"] != now.UTC().Format(time.RFC3339Nano) {
		t.Errorf("doc1.created_at: %v", doc1["created_at"])
	}
	dataMap, _ := doc1["data"].(map[string]any)
	if dataMap["host"] != "1.2.3.4" {
		t.Errorf("doc1.data.host: %v", dataMap["host"])
	}
	// 第 3 行 = meta with _id=id-2
	var meta2 map[string]any
	if err := json.Unmarshal([]byte(lines[2]), &meta2); err != nil {
		t.Fatalf("decode meta2: %v", err)
	}
	idxOp2, _ := meta2["index"].(map[string]any)
	if idxOp2["_id"] != "id-2" {
		t.Errorf("meta2._id: want id-2, got %v", idxOp2["_id"])
	}
}

func TestIndexer_Index_EmptyNoOp(t *testing.T) {
	client, stub, srv := newStubClient(t)
	defer srv.Close()

	idx, err := New(client)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := idx.Index(context.Background(), nil); err != nil {
		t.Fatalf("Index nil: %v", err)
	}
	if err := idx.Index(context.Background(), []*domain.ScanResult{}); err != nil {
		t.Fatalf("Index empty: %v", err)
	}
	if len(stub.requests) != 0 {
		t.Errorf("want 0 requests for empty, got %d", len(stub.requests))
	}
}

func TestIndexer_Index_5xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	raw, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{srv.URL},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	idx, err := New(&es.Client{Client: raw})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = idx.Index(context.Background(), []*domain.ScanResult{
		{ID: "x", TaskID: "t", AssignmentID: "a", NodeID: "n", Kind: "port_scan", Data: map[string]any{"k": "v"}, CreatedAt: time.Now()},
	})
	if err == nil {
		t.Fatal("expected error on 5xx")
	}
}

func TestNew_NilClient(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("want err on nil client")
	}
	if _, err := New(&es.Client{}); err == nil {
		t.Error("want err on zero client (Client field nil)")
	}
}
