.PHONY: all build server node test test-race lint vet vuln tidy fmt clean run-server run-node

VERSION ?= dev
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

PKG     := github.com/ffff5sec/RedMatrix
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.BuildDate=$(DATE)

GO_BUILD := go build -trimpath -ldflags "$(LDFLAGS)"

# ============= 默认 =============
all: lint test build

# ============= 构建 =============
build: server node

server:
	@mkdir -p bin
	$(GO_BUILD) -o bin/redmatrix-server ./cmd/server

node:
	@mkdir -p bin
	$(GO_BUILD) -o bin/redmatrix-node ./cmd/node

# ============= 测试 =============
test:
	go test ./...

test-race:
	go test -race -coverprofile=coverage.out ./...

# ============= 静态分析 =============
vet:
	go vet ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; skipping. Install: https://golangci-lint.run"; exit 0; }
	golangci-lint run

vuln:
	@command -v govulncheck >/dev/null 2>&1 || { echo "govulncheck not installed; install: go install golang.org/x/vuln/cmd/govulncheck@latest"; exit 1; }
	govulncheck ./...

fmt:
	gofmt -s -w .

# ============= 依赖 =============
tidy:
	go mod tidy

# ============= 运行 =============
run-server: server
	./bin/redmatrix-server

run-node: node
	./bin/redmatrix-node

# ============= 清理 =============
clean:
	rm -rf bin/ coverage.out
