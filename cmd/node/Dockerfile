# RedMatrix Agent (cmd/node) 多阶段镜像。
#
# Build:
#   docker build -t redmatrix-node:dev -f cmd/node/Dockerfile .
#
# Run（dev 同主机）：
#   docker run --rm -d \
#     --name rm-agent \
#     --network=host \
#     -v rm-agent-data:/data \
#     -e REDMATRIX_SERVER_URL=http://127.0.0.1:8080 \
#     -e REDMATRIX_NODE_AGENT_URL=https://127.0.0.1:9090 \
#     -e REDMATRIX_NODE_DATA_DIR=/data \
#     -e REDMATRIX_NODE_TOKEN=<rmnode_xxx>      \
#     -e REDMATRIX_NODE_NAME=<unique-per-tenant> \
#     redmatrix-node:dev
#
# 注意：mTLS server cert SAN 在 dev 默认是 IP 127.0.0.1 + DNS localhost；
# Agent 用 URL 里的 IP 作 ServerName 自动匹配 IP SAN。生产换成真域名时
# 再传 REDMATRIX_MTLS_SERVER_NAME=<dns> override。

FROM golang:1.25.10-alpine AS build

WORKDIR /src
RUN apk add --no-cache git

# GOPROXY：默认走官方；构建主机在墙内可 ARG 覆盖：
#   docker build --build-arg GOPROXY=https://goproxy.cn,direct ...
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# go mod cache 友好：先拷依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 拷源码 + 静态编译（CGO=0 让 alpine/scratch 直接跑）
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/ffff5sec/RedMatrix/internal/version.Version=${VERSION}" \
    -o /out/redmatrix-node ./cmd/node

# === Runtime ===
FROM alpine:3.20

# nmap 是 PR-S9 port_scan 真插件依赖；缺席时 agent 自动回落 mock。
# ca-certificates: HTTPS 出站 + mTLS root 校验
RUN apk add --no-cache ca-certificates nmap && \
    addgroup -S agent && adduser -S agent -G agent

COPY --from=build /out/redmatrix-node /usr/local/bin/redmatrix-node

# 默认数据目录；运行时一般 -v 覆盖让 cert 持久
RUN mkdir -p /data && chown agent:agent /data
VOLUME ["/data"]
USER agent

ENTRYPOINT ["/usr/local/bin/redmatrix-node"]
