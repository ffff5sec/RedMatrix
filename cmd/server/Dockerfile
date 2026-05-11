# RedMatrix Server (cmd/server) 多阶段生产镜像（PR-S19-A）。
#
# Build:
#   docker build -t redmatrix-server:dev -f cmd/server/Dockerfile .
#
# 墙内：
#   docker build --build-arg GOPROXY=https://goproxy.cn,direct ...
#
# 生产 Run（与 docker-compose.prod.yml 配套；本地 dev 用 `go run ./cmd/server`
# + dev/docker-compose.yml 起底层服务即可，不需要此镜像）：
#   docker run --rm -d \
#     --name redmatrix-server \
#     -p 8080:8080 -p 9090:9090 \
#     --env-file .env.prod \
#     -v rm-server-data:/data \
#     redmatrix-server:dev
#
# 数据目录约定：
#   /data/pki    — tenancy CA + leaf 私钥（启动期生成 / 持久）
#
# 镜像安全：
#   - 非 root 运行（user=server）
#   - alpine 3.20 基础，仅装 ca-certificates（HTTPS 出站 ES/MinIO/registry 必需）
#   - 二进制静态编译 + symbol 表 strip（-s -w）减体积
#
# 镜像可重现性（生产建议）：
#   - 升级 Go 时显式改 FROM golang:X.Y.Z-alpine
#   - 生产部署应 pin 镜像 sha256（cmd: docker pull alpine:3.20 + docker inspect 取 digest）

# === Build stage ===
FROM golang:1.25.10-alpine AS build

WORKDIR /src
RUN apk add --no-cache git

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# go mod cache 友好
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X github.com/ffff5sec/RedMatrix/internal/version.Version=${VERSION}" \
    -o /out/redmatrix-server ./cmd/server

# === Runtime ===
FROM alpine:3.20

# ca-certificates: server 出站到 ES / MinIO / 注册中心（如有）必需
RUN apk add --no-cache ca-certificates && \
    addgroup -S server && adduser -S server -G server

COPY --from=build /out/redmatrix-server /usr/local/bin/redmatrix-server

# /data 用于 tenancy CA / leaf 私钥持久（生产应挂 named volume 或 hostPath）
RUN mkdir -p /data && chown server:server /data
VOLUME ["/data"]
USER server

# 业务端口：HTTP 8080 / mTLS 9090
EXPOSE 8080 9090

ENTRYPOINT ["/usr/local/bin/redmatrix-server"]
