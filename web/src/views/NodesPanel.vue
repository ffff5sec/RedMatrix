<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue';
import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import { useToast } from '@/composables/useToast';
import type { Node, RegistrationToken } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const toast = useToast();

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const nodes = ref<Node[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const filterStatus = ref('');
const filterKeyword = ref('');

const loading = ref(false);

async function refresh() {
  loading.value = true;
  try {
    const r = await tenancyClient.listNodes({
      tenantId: DEFAULT_TENANT_ID,
      status: filterStatus.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    nodes.value = r.nodes;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// === 自动刷新（节点活性视图）===
//
// MVP：固定 30s 轮询。后端 Heartbeat 默认 30s，这里同频抓 List 即可看到状态切换。
// 更精细要：可选用户暂停 + 服务端 SSE / WebSocket 推送（PR-W4 之后再说）。
const REFRESH_INTERVAL_MS = 30_000;
const nowTick = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

onMounted(() => {
  refreshTimer = setInterval(refresh, REFRESH_INTERVAL_MS);
  // 1s tick 让"X 秒前"持续刷新（避免 30s 跳跃感）
  tickTimer = setInterval(() => {
    nowTick.value = Date.now();
  }, 1_000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (tickTimer) clearInterval(tickTimer);
});

// === Create ===
const showCreate = ref(false);
const newN = ref({ name: '', version: '', capabilities: '' });
const submitting = ref(false);

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  try {
    const caps = newN.value.capabilities
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    await tenancyClient.createNode({
      tenantId: DEFAULT_TENANT_ID,
      name: newN.value.name,
      version: newN.value.version,
      capabilities: caps,
    });
    showCreate.value = false;
    newN.value = { name: '', version: '', capabilities: '' };
    toast.success('节点已注册（pending）');
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function enable(id: string, name: string) {
  try {
    await tenancyClient.enableNode({ id });
    toast.success(`${name} 已启用（pending）`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function disable(id: string, name: string) {
  if (!confirm(`禁用 ${name}？`)) return;
  try {
    await tenancyClient.disableNode({ id });
    toast.warning(`${name} 已禁用`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function del(id: string, name: string) {
  if (!confirm(`删除节点 ${name}？该操作不可撤销（MVP 软删，名称可重新使用）。`)) return;
  try {
    await tenancyClient.deleteNode({ id });
    toast.success(`${name} 已删除`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

function fmt(t?: { toDate(): Date }) {
  return t ? t.toDate().toLocaleString() : '-';
}

function statusBadge(s: string) {
  switch (s) {
    case 'online': return 'green';
    case 'pending': return 'amber';
    case 'offline': return 'amber';
    case 'disabled': return 'red';
    default: return '';
  }
}

// 节点活性指示点：online=绿、pending=黄、offline=灰、disabled=红
function statusDot(s: string) {
  switch (s) {
    case 'online': return 'dot-green';
    case 'pending': return 'dot-amber';
    case 'offline': return 'dot-gray';
    case 'disabled': return 'dot-red';
    default: return '';
  }
}

// === RegistrationToken（节点接入）===

const showTokens = ref(false);
const tokens = ref<RegistrationToken[]>([]);
const tokensLoading = ref(false);
const newToken = ref({ name: '', ttlHours: 1 });
const tokenSubmitting = ref(false);
// PR-S73 新创建的 token + server 端点（用来渲染一键安装命令）
const lastPlaintext = ref<{
  name: string;
  plaintext: string;
  serverUrl: string;
  nodeAgentUrl: string;
  mtlsServerName: string;
} | null>(null);
const snippetTab = ref<'binary' | 'docker' | 'manual'>('binary');

async function refreshTokens() {
  tokensLoading.value = true;
  try {
    const r = await tenancyClient.listRegistrationTokens({ tenantId: DEFAULT_TENANT_ID });
    tokens.value = r.tokens;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    tokensLoading.value = false;
  }
}

async function toggleTokens() {
  showTokens.value = !showTokens.value;
  if (showTokens.value) await refreshTokens();
}

async function createToken() {
  if (tokenSubmitting.value) return;
  tokenSubmitting.value = true;
  try {
    const r = await tenancyClient.createRegistrationToken({
      tenantId: DEFAULT_TENANT_ID,
      name: newToken.value.name,
      ttlSeconds: BigInt(Math.max(60, Math.min(86400, newToken.value.ttlHours * 3600))),
    });
    lastPlaintext.value = {
      name: newToken.value.name,
      plaintext: r.plaintext,
      serverUrl: r.serverUrl,
      nodeAgentUrl: r.nodeAgentUrl,
      mtlsServerName: r.mtlsServerName,
    };
    newToken.value = { name: '', ttlHours: 1 };
    toast.success(`令牌 ${lastPlaintext.value.name} 已生成（plaintext 仅显示一次）`);
    await refreshTokens();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    tokenSubmitting.value = false;
  }
}

async function revokeToken(id: string, name: string) {
  if (!confirm(`撤销注册令牌 ${name}？已撤销不可恢复（请重新创建）。`)) return;
  try {
    await tenancyClient.revokeRegistrationToken({ id });
    toast.warning(`令牌 ${name} 已撤销`);
    await refreshTokens();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

function copyText(s: string) {
  navigator.clipboard?.writeText(s);
}

// PR-S73：用 token + endpoint 生成 3 种一键安装命令片段。
function snippetBinary(t: NonNullable<typeof lastPlaintext.value>, nodeName: string): string {
  const sanFlag = t.mtlsServerName ? ` \\\n  --mtls-server-name '${t.mtlsServerName}'` : '';
  return [
    '# 1) 拷贝 redmatrix-node 二进制到本机（or 用 docker / docker compose 见其他 tab）',
    '# 2) 准备 data 目录持久 leaf cert',
    'mkdir -p /var/lib/redmatrix-node',
    '',
    './redmatrix-node \\',
    `  --server-url '${t.serverUrl}' \\`,
    `  --node-agent-url '${t.nodeAgentUrl}' \\`,
    `  --token '${t.plaintext}' \\`,
    `  --node-name '${nodeName || 'NODE-NAME-HERE'}' \\`,
    `  --data-dir /var/lib/redmatrix-node${sanFlag}`,
  ].join('\n');
}

function snippetDocker(t: NonNullable<typeof lastPlaintext.value>, nodeName: string): string {
  const sanEnv = t.mtlsServerName ? `\\\n  -e REDMATRIX_MTLS_SERVER_NAME='${t.mtlsServerName}' ` : '';
  return [
    '# Docker 单容器（生产建议见 deploy/docker-compose.node.yml）',
    'docker volume create redmatrix-node-data',
    '',
    'docker run -d \\',
    '  --name redmatrix-node \\',
    '  --restart unless-stopped \\',
    '  -v redmatrix-node-data:/data \\',
    '  -v /opt/redmatrix/plugins:/opt/plugins:ro \\',
    `  -e REDMATRIX_SERVER_URL='${t.serverUrl}' \\`,
    `  -e REDMATRIX_NODE_AGENT_URL='${t.nodeAgentUrl}' \\`,
    `  -e REDMATRIX_NODE_TOKEN='${t.plaintext}' \\`,
    `  -e REDMATRIX_NODE_NAME='${nodeName || 'NODE-NAME-HERE'}' \\`,
    '  -e REDMATRIX_NODE_DATA_DIR=/data \\',
    `  -e REDMATRIX_PLUGIN_DIR=/opt/plugins ${sanEnv}\\`,
    '  ghcr.io/your-org/redmatrix-node:prod',
  ].join('\n');
}

function snippetManual(t: NonNullable<typeof lastPlaintext.value>): string {
  return [
    '# 配置项（env 或 flag 任选）：',
    `# server URL          = ${t.serverUrl}`,
    `# node agent URL      = ${t.nodeAgentUrl}`,
    `# token (一次性，10 分钟内 redeem) = ${t.plaintext}`,
    t.mtlsServerName ? `# mtls server name override = ${t.mtlsServerName}` : '# mtls server name override = (留空)',
    '',
    '# 节点名同租户内唯一；接入成功后 leaf cert 持久在 data dir，重启不需重 redeem。',
  ].join('\n');
}

function currentSnippet(): string {
  if (!lastPlaintext.value) return '';
  const name = lastPlaintext.value.name;
  switch (snippetTab.value) {
    case 'binary': return snippetBinary(lastPlaintext.value, name);
    case 'docker': return snippetDocker(lastPlaintext.value, name);
    case 'manual': return snippetManual(lastPlaintext.value);
  }
}

function tokenStatusOf(t: RegistrationToken): { text: string; cls: string } {
  if (t.revokedAt) return { text: 'revoked', cls: 'red' };
  if (t.usedAt) return { text: 'used', cls: 'green' };
  if (t.expiresAt && t.expiresAt.toDate() < new Date()) return { text: 'expired', cls: 'amber' };
  return { text: 'pending', cls: 'amber' };
}
</script>

<template>
  <div v-if="!authStore.isSuperAdmin() && !authStore.isAuditor()" class="card">
    <p class="muted">仅 SuperAdmin / TenantAuditor 可访问。</p>
  </div>

  <template v-else>
    <div class="card">
      <div class="row" style="justify-content: space-between">
        <h2>注册令牌</h2>
        <button @click="toggleTokens">
          {{ showTokens ? '收起' : '展开' }}
        </button>
      </div>
      <p class="muted">
        SA 生成一次性令牌；真节点（Agent）首次连接时凭此换取节点身份（PR-T4-D 加 mTLS 证书）。
      </p>

      <div v-if="showTokens">
        <div v-if="lastPlaintext" class="info">
          <strong>新令牌已创建（仅本次显示）·{{ lastPlaintext.name }}</strong>
          <div style="margin-top: 6px">Token：</div>
          <code class="mono" style="display: block; margin-top: 4px; word-break: break-all">{{ lastPlaintext.plaintext }}</code>
          <button style="margin-top: 8px" @click="copyText(lastPlaintext.plaintext)">复制 Token</button>
          <button style="margin-left: 4px" @click="lastPlaintext = null">关闭</button>

          <!-- PR-S73：一键安装命令片段 -->
          <div style="margin-top: 16px">
            <strong>在节点机器上执行：</strong>
            <div class="row" style="gap: 4px; margin-top: 6px">
              <button :class="{ tab: true, 'tab-active': snippetTab === 'binary' }" @click="snippetTab = 'binary'">Linux binary</button>
              <button :class="{ tab: true, 'tab-active': snippetTab === 'docker' }" @click="snippetTab = 'docker'">Docker</button>
              <button :class="{ tab: true, 'tab-active': snippetTab === 'manual' }" @click="snippetTab = 'manual'">配置项</button>
              <button style="margin-left: auto" @click="copyText(currentSnippet())">复制命令</button>
            </div>
            <pre class="snippet">{{ currentSnippet() }}</pre>
            <p class="muted" style="margin-top: 4px; font-size: 12px">
              Token 一次性消费；10 分钟内 redeem。接入成功后 leaf cert 持久在 data dir，重启不需重新 redeem。
              节点名同租户内唯一。
            </p>
          </div>
        </div>

        <div v-if="authStore.isSuperAdmin()" class="row" style="margin: 12px 0">
          <input
            v-model="newToken.name"
            placeholder="令牌名（如 q1-batch）"
            :disabled="tokenSubmitting"
          />
          <input
            v-model.number="newToken.ttlHours"
            type="number"
            min="1"
            max="24"
            :disabled="tokenSubmitting"
            style="width: 80px"
          />
          <span class="muted">小时（1-24）</span>
          <button
            class="primary"
            :disabled="tokenSubmitting || !newToken.name"
            @click="createToken"
          >
            {{ tokenSubmitting ? '生成中…' : '生成令牌' }}
          </button>
        </div>

        <table v-if="tokens.length > 0">
          <thead>
            <tr>
              <th>名称</th>
              <th>状态</th>
              <th>过期</th>
              <th>已用</th>
              <th>创建</th>
              <th v-if="authStore.isSuperAdmin()"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tokens" :key="t.id">
              <td>{{ t.name }}</td>
              <td>
                <span class="badge" :class="tokenStatusOf(t).cls">{{ tokenStatusOf(t).text }}</span>
              </td>
              <td class="muted">{{ fmt(t.expiresAt) }}</td>
              <td class="muted">{{ fmt(t.usedAt) }}</td>
              <td class="muted">{{ fmt(t.createdAt) }}</td>
              <td v-if="authStore.isSuperAdmin()">
                <button
                  v-if="!t.revokedAt && !t.usedAt"
                  class="danger"
                  @click="revokeToken(t.id, t.name)"
                >
                  撤销
                </button>
                <span v-else class="muted">—</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else-if="!tokensLoading" class="muted">尚无令牌。</p>
      </div>
    </div>

    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>节点</h2>
        <span class="live-indicator" :class="{ pulsing: !loading }" :title="`每 ${REFRESH_INTERVAL_MS / 1000}s 自动刷新`">
          <span class="dot dot-green" />
          实时 · {{ REFRESH_INTERVAL_MS / 1000 }}s
        </span>
      </div>
      <div class="row">
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option value="pending">pending</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="disabled">disabled</option>
        </select>
        <input
          v-model="filterKeyword"
          placeholder="按名称模糊搜索"
          :disabled="loading"
          style="width: 240px"
        />
        <button :disabled="loading" @click="page = 1; refresh()">查询</button>
        <button v-if="authStore.isSuperAdmin()" class="primary" @click="showCreate = true">
          注册节点
        </button>
      </div>

      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>版本</th>
            <th>能力</th>
            <th>状态</th>
            <th>最后心跳</th>
            <th>注册时间</th>
            <th v-if="authStore.isSuperAdmin()">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="n in nodes" :key="n.id">
            <td>
              <router-link :to="`/nodes/${n.id}`" class="node-link">{{ n.name }}</router-link>
            </td>
            <td class="muted">{{ n.version || '-' }}</td>
            <td>
              <code v-if="n.capabilities.length > 0">{{ n.capabilities.join(', ') }}</code>
              <span v-else class="muted">-</span>
            </td>
            <td>
              <span class="status-cell">
                <span class="dot" :class="statusDot(n.status)" />
                <span class="badge" :class="statusBadge(n.status)">{{ n.status }}</span>
              </span>
            </td>
            <td>
              <span
                v-if="n.lastSeenAt"
                :title="formatAbsoluteTime(n.lastSeenAt)"
                :class="n.status === 'online' ? '' : 'muted'"
              >
                {{ formatRelativeTime(n.lastSeenAt, nowTick) }}
              </span>
              <span v-else class="muted">从未上报</span>
            </td>
            <td class="muted">{{ fmt(n.createdAt) }}</td>
            <td v-if="authStore.isSuperAdmin()">
              <div class="row" style="gap: 4px">
                <button v-if="n.status === 'disabled'" @click="enable(n.id, n.name)">
                  启用
                </button>
                <button v-else @click="disable(n.id, n.name)">禁用</button>
                <button class="danger" @click="del(n.id, n.name)">删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="nodes.length === 0">
            <td colspan="7" class="muted" style="text-align: center; padding: 24px">
              暂无节点
            </td>
          </tr>
        </tbody>
      </table>

      <div class="row" style="justify-content: space-between">
        <span class="muted">共 {{ total }} 个节点</span>
        <div class="row">
          <button :disabled="page <= 1 || loading" @click="page--; refresh()">上一页</button>
          <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
          <button :disabled="page >= totalPages() || loading" @click="page++; refresh()">下一页</button>
        </div>
      </div>

      <p class="muted">
        MVP：手动注册节点。完整 RegistrationToken / mTLS 流程见 PR-T4-B/D。
      </p>
    </div>

    <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
      <div class="modal">
        <h2>注册节点</h2>
        <div class="stack">
          <div class="row">
            <span class="label">名称</span>
            <input v-model="newN.name" placeholder="租户内唯一" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">版本</span>
            <input v-model="newN.version" placeholder="可选，e.g. 1.0.0" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">能力</span>
            <input
              v-model="newN.capabilities"
              placeholder="scan:web, scan:port（逗号分隔）"
              :disabled="submitting"
              style="flex: 1"
            />
          </div>
          <p class="muted">注册后状态为 pending，等待真节点上线 / SA 手动启用。</p>
          <div class="row">
            <button class="primary" :disabled="submitting || !newN.name" @click="create">
              {{ submitting ? '创建中…' : '注册' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>

<style scoped>
.status-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.dot-green { background: #22c55e; box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16); }
.dot-amber { background: #f59e0b; box-shadow: 0 0 0 3px rgba(245, 158, 11, 0.18); }
.dot-gray  { background: #9ca3af; }
.dot-red   { background: #ef4444; box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.18); }

.live-indicator {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: var(--muted, #6b7280);
}

.node-link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.node-link:hover {
  text-decoration: underline;
}

.live-indicator.pulsing .dot-green {
  animation: pulse 1.6s ease-in-out infinite;
}

@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16); }
  50%      { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.04); }
}
/* PR-S73: install snippet */
.tab {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 13px;
  background: rgba(0,0,0,0.04);
}
.tab-active {
  background: rgba(59, 130, 246, 0.16);
  color: #1d4ed8;
  font-weight: 500;
}
.snippet {
  background: #0d1117;
  color: #e6edf3;
  padding: 12px;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
  margin-top: 8px;
  overflow-x: auto;
  white-space: pre;
}
</style>
