.PHONY: all build server node test test-race test-integration lint vet vuln tidy fmt clean run-server run-node proto proto-lint proto-check tools

# 让 Makefile 子 shell 能找到 go install 出来的 buf / protoc-gen-* 等
GOBIN   := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

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

# 集成测试（用 testcontainers 起真 PG / Redis / ES 等）。需 Docker daemon 在线。
# 单独 tag 与 unit 测试隔离：默认 `make test` 不跑这些。
test-integration:
	go test -tags=integration -count=1 ./...

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

# ============= Proto =============
# 工具安装（首次或 CI 缓存失效后调用）
tools:
	go install github.com/bufbuild/buf/cmd/buf@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.19.2

# 完整 proto 流水线：格式化 + lint + 代码生成
proto:
	@command -v buf >/dev/null 2>&1 || { echo "buf not installed; run 'make tools'"; exit 1; }
	buf format -w
	buf lint
	buf generate
	@echo "✓ proto generated to gen/proto/"

# 仅 lint + 格式 diff（CI 用）
proto-lint:
	buf lint
	buf format -d

# CI 漂移检查：生成代码后 git diff --exit-code 守底
proto-check:
	buf format -d
	buf lint
	buf generate
	@git diff --exit-code -- gen/ || { echo "✗ generated code drift; run 'make proto' locally and commit"; exit 1; }

# ============= 本地开发栈 =============
# dev-up：起 PG + Redis + ES + MinIO + 9 bucket 自动建好
# dev-down：停容器（保留 volume）
# dev-reset：停 + 删 volume（回到首启状态，roles 重新初始化）
# dev-server：source dev/.env.dev 后跑 server
dev-up:
	docker compose -f dev/docker-compose.yml up -d
	@echo "✓ dev stack 启动；首启 ES 需 30s+ 才会 healthy"
	@echo "  查 bucket 建好: docker compose -f dev/docker-compose.yml logs minio-bootstrap"

dev-down:
	docker compose -f dev/docker-compose.yml down

dev-reset:
	docker compose -f dev/docker-compose.yml down -v

dev-server:
	@command -v bash >/dev/null 2>&1 || { echo "需要 bash"; exit 1; }
	@bash -c 'set -a && source dev/.env.dev && set +a && go run ./cmd/server'

# ============= 清理 =============
clean:
	rm -rf bin/ coverage.out
