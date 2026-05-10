#!/usr/bin/env bash
# integration-e2e.sh —— RedMatrix 全链路集成 e2e（PR-S13）。
#
# 前置：
#   - dev/docker-compose.yml 起的 PG / Redis / ES / MinIO 健康
#   - /tmp/redmatrix-server 已构建并运行（监听 :8080 + :9090）
#   - 已 docker build redmatrix-node:integ 镜像（含 nmap/subfinder/httpx）
#   - 本机 admin 密码 = DemoBootstrapPwd1!（dev/.env.dev 默认）
#
# 流程：
#   1. login 拿 JWT
#   2. 从 ListProjects 拿 project id
#   3. 创建 RegistrationToken（默认租户）
#   4. docker run agent 容器（host 网络，token 注入）
#   5. 等 node 上线（HeartbeatService 列表含本节点 + status=online）
#   6. 创建 4 类 task（每类一条）
#   7. 轮询任务 status 直到全终态
#   8. 输出验收：scan_results 计数 / assets 计数 / ES doc 数 / 关键样本

set -euo pipefail

# === 配置 ===
SERVER_URL="${SERVER_URL:-http://127.0.0.1:8080}"
NODE_AGENT_URL="${NODE_AGENT_URL:-https://127.0.0.1:9090}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-DemoBootstrapPwd1!}"
AGENT_IMAGE="${AGENT_IMAGE:-redmatrix-node:integ}"
AGENT_NAME="${AGENT_NAME:-rm-agent-integ}"
TENANT_ID="${TENANT_ID:-00000000-0000-0000-0000-000000000001}"
WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}" # task 全完成最长等待秒
PORT_SCAN_TARGET="${PORT_SCAN_TARGET:-127.0.0.1}"
PORT_SCAN_PORTS="${PORT_SCAN_PORTS:-22,80,9200}"
SUBDOMAIN_TARGET="${SUBDOMAIN_TARGET:-example.com}"
WEB_TARGET="${WEB_TARGET:-https://example.com}"

curl_json() {
  curl -s --noproxy '*' -H "Content-Type: application/json" "$@"
}

log()  { printf '\033[36m[e2e]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m[!!]\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[31m[xx]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  command -v "$1" >/dev/null 2>&1 || fail "需要工具: $1"
}

require curl
require docker
require jq

# === 1. login ===
log "1/8 login admin..."
CID=$(curl_json -X POST "$SERVER_URL/redmatrix.identity.v1.IdentityService/GetCaptcha" -d '{}' | jq -r .captchaId)
ANS=$(docker exec redmatrix-dev-redis-1 redis-cli GET "global:captcha:$CID")
TOKEN=$(curl_json -X POST "$SERVER_URL/redmatrix.identity.v1.IdentityService/Login" \
  -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"captchaId\":\"$CID\",\"captchaAnswer\":\"$ANS\"}" \
  | jq -r .accessToken)
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || fail "login 失败"
AUTH=( -H "Authorization: Bearer $TOKEN" )

# === 2. project ===
log "2/8 取项目..."
PROJ_ID=$(curl_json -X POST "$SERVER_URL/redmatrix.tenancy.v1.TenancyService/ListProjects" \
  "${AUTH[@]}" \
  -d "{\"tenantId\":\"$TENANT_ID\",\"page\":1,\"pageSize\":1}" \
  | jq -r '.projects[0].id')
[ -n "$PROJ_ID" ] && [ "$PROJ_ID" != "null" ] || fail "无项目；先 dev seed"
log "  PROJ_ID=$PROJ_ID"

# === 3. registration token ===
log "3/8 创建注册 token..."
RAW_TOKEN=$(curl_json -X POST "$SERVER_URL/redmatrix.tenancy.v1.TenancyService/CreateRegistrationToken" \
  "${AUTH[@]}" \
  -d "{\"tenantId\":\"$TENANT_ID\",\"name\":\"integ-$(date +%s)\",\"ttlSeconds\":3600}" \
  | jq -r .plaintext)
[ -n "$RAW_TOKEN" ] && [ "$RAW_TOKEN" != "null" ] || fail "token 创建失败"
log "  token=${RAW_TOKEN:0:24}..."

# === 4. agent 容器 ===
log "4/8 启 agent 容器..."
docker rm -f "$AGENT_NAME" >/dev/null 2>&1 || true
docker volume rm "$AGENT_NAME-data" >/dev/null 2>&1 || true
docker volume create "$AGENT_NAME-data" >/dev/null
NODE_NAME="integ-$(date +%s)"
docker run --rm -d \
  --name "$AGENT_NAME" \
  --network=host \
  -v "$AGENT_NAME-data":/data \
  -e REDMATRIX_SERVER_URL="$SERVER_URL" \
  -e REDMATRIX_NODE_AGENT_URL="$NODE_AGENT_URL" \
  -e REDMATRIX_NODE_DATA_DIR=/data \
  -e REDMATRIX_NODE_TOKEN="$RAW_TOKEN" \
  -e REDMATRIX_NODE_NAME="$NODE_NAME" \
  "$AGENT_IMAGE" >/dev/null
log "  agent name=$NODE_NAME"

# === 5. 等 node 上线 ===
log "5/8 等 node 注册 + 心跳上线（最多 30s）..."
NODE_ID=""
for i in $(seq 1 30); do
  NODE_ID=$(curl_json -X POST "$SERVER_URL/redmatrix.tenancy.v1.TenancyService/ListNodes" \
    "${AUTH[@]}" \
    -d "{\"tenantId\":\"$TENANT_ID\",\"page\":1,\"pageSize\":50}" \
    | jq -r ".nodes[] | select(.name==\"$NODE_NAME\") | .id" | head -1)
  if [ -n "$NODE_ID" ]; then
    log "  node id=$NODE_ID"
    break
  fi
  sleep 1
done
[ -n "$NODE_ID" ] || { docker logs "$AGENT_NAME" | tail -20 >&2; fail "agent 未注册成功"; }

# 让 project allowed_nodes 只允许本次新 agent，避开历史挂掉的 integ-* node
# （否则 task 会被派给已死 node 的 assignment，task 状态卡 pending）
log "  把 project allowedNodes 限定到本次 node..."
curl_json -X POST "$SERVER_URL/redmatrix.tenancy.v1.TenancyService/SetProjectAllowedNodes" \
  "${AUTH[@]}" \
  -d "{\"projectId\":\"$PROJ_ID\",\"nodeIds\":[\"$NODE_ID\"]}" >/dev/null

# === 6. 创建 4 类 task ===
log "6/8 创建 4 类 task..."
create_task() {
  local kind=$1 target=$2 target_kind=$3 name=$4
  curl_json -X POST "$SERVER_URL/redmatrix.scan.v1.ScanService/CreateScanTask" \
    "${AUTH[@]}" \
    -d "{\"projectId\":\"$PROJ_ID\",\"name\":\"$name\",\"kind\":\"$kind\",\"target\":\"$target\",\"targetKind\":\"$target_kind\"}" \
    | jq -r .task.id
}

T_PORT=$(create_task port_scan "$PORT_SCAN_TARGET" ip "integ-port-$(date +%s)")
T_FP=$(create_task fingerprint "$WEB_TARGET" url "integ-fp-$(date +%s)")
T_WC=$(create_task web_crawl "$WEB_TARGET" url "integ-wc-$(date +%s)")
T_SUB=$(create_task subdomain "$SUBDOMAIN_TARGET" host "integ-sub-$(date +%s)")
log "  port_scan=$T_PORT"
log "  fingerprint=$T_FP"
log "  web_crawl=$T_WC"
log "  subdomain=$T_SUB"

# === 7. 轮询 status ===
log "7/8 等 4 task 全终态（pending/running 视为未完，最多 ${WAIT_TIMEOUT}s）..."
all_done=0
for i in $(seq 1 "$WAIT_TIMEOUT"); do
  remaining=0
  for t in "$T_PORT" "$T_FP" "$T_WC" "$T_SUB"; do
    s=$(curl_json -X POST "$SERVER_URL/redmatrix.scan.v1.ScanService/GetScanTask" \
      "${AUTH[@]}" -d "{\"id\":\"$t\"}" | jq -r .task.status)
    case "$s" in
      pending|running) remaining=$((remaining + 1)) ;;
    esac
  done
  if [ "$remaining" -eq 0 ]; then
    all_done=1; break
  fi
  if [ $((i % 5)) -eq 0 ]; then
    log "  $i s — 还有 $remaining 个未完..."
  fi
  sleep 1
done
[ "$all_done" -eq 1 ] || warn "部分 task 未在 ${WAIT_TIMEOUT}s 内完成；继续输出现状"

# === 8. 验收 ===
log "8/8 验收..."
echo "=== task 终态 ==="
for t in "$T_PORT" "$T_FP" "$T_WC" "$T_SUB"; do
  curl_json -X POST "$SERVER_URL/redmatrix.scan.v1.ScanService/GetScanTask" \
    "${AUTH[@]}" -d "{\"id\":\"$t\"}" \
    | jq -c '{id:.task.id, name:.task.name, kind:.task.kind, status:.task.status}'
done

echo
echo "=== scan_results 计数（按 kind）==="
docker exec redmatrix-dev-pg-1 psql -U postgres -d redmatrix -t -c "
  SELECT kind, count(*) FROM scan_results
  WHERE task_id IN ('$T_PORT'::uuid, '$T_FP'::uuid, '$T_WC'::uuid, '$T_SUB'::uuid)
  GROUP BY kind ORDER BY kind"

echo
echo "=== assets 派生（本次相关）==="
docker exec redmatrix-dev-pg-1 psql -U postgres -d redmatrix -t -c "
  SELECT kind, count(*) FROM assets
  WHERE project_id = '$PROJ_ID'::uuid
  GROUP BY kind ORDER BY kind"

echo
echo "=== ES scan-results 索引文档数 ==="
curl -s --noproxy '*' "http://127.0.0.1:9200/scan-results/_count" | jq

echo
echo "=== port_scan 真插件证据（从结果取一条 banner，看是否非 mock）==="
docker exec redmatrix-dev-pg-1 psql -U postgres -d redmatrix -t -c "
  SELECT data->>'host' AS host, data->>'port' AS port,
         data->>'service' AS service, data->>'banner' AS banner
  FROM scan_results WHERE task_id = '$T_PORT'::uuid LIMIT 5"

echo
echo "=== fingerprint 真插件证据 ==="
docker exec redmatrix-dev-pg-1 psql -U postgres -d redmatrix -t -c "
  SELECT data->>'target' AS target, data->>'webserver' AS webserver,
         data->'tech' AS tech
  FROM scan_results WHERE task_id = '$T_FP'::uuid LIMIT 3"

log "完成。检查上面输出：banner / webserver / tech 字段如非 'mock' / 'Vue.js' 字面值即真插件路径。"

# 留容器供查 docker logs；CI 路径可加 --rm 时自清
log "清理：docker rm -f $AGENT_NAME（人手执行；保留容器便于排查）"
