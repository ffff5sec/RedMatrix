<script setup lang="ts">
// NodeDetail —— 节点详情页（PR-W6）。
//
// 路由：/nodes/:id
//
// 内容：
//   - 顶部 Node header：名称 / 状态点 / 版本 / 心跳相对时间 / 操作按钮
//   - 能力 chips
//   - 证书历史表（issued / expires / fingerprint / 状态）
//
// 30s 自动刷新；权限：SA / Auditor 才能进（路由 meta 守卫；非该角色返 403）。
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type {
  Node,
  NodeCertificate,
} from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const route = useRoute();
const router = useRouter();
const toast = useToast();

const REFRESH_INTERVAL_MS = 30_000;

const nodeId = computed(() => String(route.params.id));
const node = ref<Node | null>(null);
const certs = ref<NodeCertificate[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());

let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

async function refresh() {
  if (!nodeId.value) return;
  loading.value = true;
  try {
    const [nodeRes, certsRes] = await Promise.all([
      tenancyClient.getNode({ id: nodeId.value }),
      tenancyClient.listNodeCertificates({ nodeId: nodeId.value }),
    ]);
    node.value = nodeRes.node ?? null;
    certs.value = certsRes.certificates;
  } catch (e) {
    toast.error('加载失败：' + errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  refresh();
  refreshTimer = setInterval(refresh, REFRESH_INTERVAL_MS);
  tickTimer = setInterval(() => {
    nowTick.value = Date.now();
  }, 1_000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (tickTimer) clearInterval(tickTimer);
});

function statusBadge(s: string) {
  switch (s) {
    case 'online': return 'green';
    case 'pending': return 'amber';
    case 'offline': return 'amber';
    case 'disabled': return 'red';
    default: return '';
  }
}
function statusDot(s: string) {
  switch (s) {
    case 'online': return 'dot-green';
    case 'pending': return 'dot-amber';
    case 'offline': return 'dot-gray';
    case 'disabled': return 'dot-red';
    default: return '';
  }
}

// === 节点操作（SA only；与 NodesPanel 同行为）===
async function disable() {
  if (!node.value) return;
  if (!confirm(`禁用 ${node.value.name}？`)) return;
  try {
    await tenancyClient.disableNode({ id: node.value.id });
    toast.warning(`${node.value.name} 已禁用`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
async function enable() {
  if (!node.value) return;
  try {
    await tenancyClient.enableNode({ id: node.value.id });
    toast.success(`${node.value.name} 已启用（pending）`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
async function del() {
  if (!node.value) return;
  if (!confirm(`删除节点 ${node.value.name}？此操作软删，名称可重用。`)) return;
  try {
    await tenancyClient.deleteNode({ id: node.value.id });
    toast.success(`${node.value.name} 已删除`);
    router.push('/nodes');
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

// === Cert 状态（前端派生：未撤 / 未过期 → active；其它走 revoked / expired）===
function certStatus(c: NodeCertificate): { text: string; cls: string } {
  if (c.revokedAt) return { text: 'revoked', cls: 'red' };
  if (c.expiresAt && c.expiresAt.toDate().getTime() < Date.now()) {
    return { text: 'expired', cls: '' };
  }
  return { text: 'active', cls: 'green' };
}

function copyText(s: string) {
  navigator.clipboard?.writeText(s);
  toast.info('已复制到剪贴板');
}

function shortFP(fp: string): string {
  if (!fp) return '-';
  return fp.slice(0, 12) + '…' + fp.slice(-6);
}
</script>

<template>
  <div class="detail">
    <div class="head">
      <button class="back" @click="router.push('/nodes')">← 返回</button>
      <span class="muted live-indicator" :title="`每 ${REFRESH_INTERVAL_MS / 1000}s 自动刷新`">
        <span class="dot dot-green pulsing" v-if="!loading" />
        <span class="dot dot-amber" v-else />
        实时 · {{ REFRESH_INTERVAL_MS / 1000 }}s
      </span>
    </div>

    <div v-if="!node && !loading" class="card empty">
      <p>节点不存在或已删除。</p>
      <button @click="router.push('/nodes')">返回节点列表</button>
    </div>

    <template v-if="node">
      <!-- Node header -->
      <div class="card node-header">
        <div class="row" style="justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px">
          <div>
            <h1 class="title">
              <span class="dot" :class="statusDot(node.status)" />
              {{ node.name }}
            </h1>
            <div class="row meta-row">
              <span class="badge" :class="statusBadge(node.status)">{{ node.status }}</span>
              <span class="muted">v{{ node.version || '–' }}</span>
              <span class="muted">·</span>
              <span class="muted">
                最后心跳：
                <span v-if="node.lastSeenAt" :title="formatAbsoluteTime(node.lastSeenAt)">
                  {{ formatRelativeTime(node.lastSeenAt, nowTick) }}
                </span>
                <span v-else>从未上报</span>
              </span>
            </div>
          </div>

          <div v-if="authStore.isSuperAdmin()" class="row" style="gap: 8px">
            <button v-if="node.status === 'disabled'" class="primary" @click="enable">启用</button>
            <button v-else @click="disable">禁用</button>
            <button class="danger" @click="del">删除</button>
          </div>
        </div>

        <div class="kv">
          <div class="kv-row"><span class="kv-k">ID</span><code>{{ node.id }}</code></div>
          <div class="kv-row"><span class="kv-k">租户</span><code>{{ node.tenantId }}</code></div>
          <div class="kv-row" v-if="node.createdAt">
            <span class="kv-k">注册时间</span>
            <span :title="formatAbsoluteTime(node.createdAt)">
              {{ formatAbsoluteTime(node.createdAt) }}（{{ formatRelativeTime(node.createdAt, nowTick) }}）
            </span>
          </div>
          <div class="kv-row" v-if="node.capabilities && node.capabilities.length > 0">
            <span class="kv-k">能力</span>
            <div class="chips">
              <code v-for="c in node.capabilities" :key="c" class="chip">{{ c }}</code>
            </div>
          </div>
        </div>
      </div>

      <!-- Cert 历史 -->
      <div class="card">
        <h2>证书历史 <span class="muted">（{{ certs.length }}）</span></h2>
        <p class="muted">
          首签来自 RegistrationToken；后续都是 Agent 自动续期（D5）。旧 cert 不主动 revoke，到期自然失效。
        </p>
        <table v-if="certs.length > 0">
          <thead>
            <tr>
              <th>状态</th>
              <th>指纹</th>
              <th>签发时间</th>
              <th>过期时间</th>
              <th>来源</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in certs" :key="c.id">
              <td>
                <span class="badge" :class="certStatus(c).cls">{{ certStatus(c).text }}</span>
              </td>
              <td>
                <code class="fp" :title="c.fingerprint">{{ shortFP(c.fingerprint) }}</code>
              </td>
              <td>
                <span :title="formatAbsoluteTime(c.issuedAt)">
                  {{ formatRelativeTime(c.issuedAt, nowTick) }}
                </span>
              </td>
              <td>
                <span :title="formatAbsoluteTime(c.expiresAt)">
                  {{ formatRelativeTime(c.expiresAt, nowTick) }}
                </span>
              </td>
              <td>
                <span v-if="c.issuedByToken" class="muted" :title="c.issuedByToken">token</span>
                <span v-else class="muted">renew</span>
              </td>
              <td>
                <button class="link-btn" @click="copyText(c.fingerprint)">复制</button>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted">尚无证书历史。</p>
      </div>
    </template>
  </div>
</template>

<style scoped>
.detail {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.back {
  background: transparent;
  border: none;
  color: var(--accent, #2563eb);
  font-size: 13px;
  cursor: pointer;
  padding: 4px 0;
}
.back:hover { text-decoration: underline; }

.title {
  font-size: 22px;
  font-weight: 600;
  margin: 0 0 6px;
  display: flex;
  align-items: center;
  gap: 10px;
}
.meta-row {
  align-items: center;
  gap: 8px;
  font-size: 13px;
}
.muted { color: var(--muted, #6b7280); }

.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.empty {
  text-align: center;
  padding: 48px 16px;
}

.kv {
  margin-top: 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-top: 12px;
  border-top: 1px solid var(--border, #e2e8f0);
}
.kv-row {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 13px;
}
.kv-k {
  width: 80px;
  color: var(--muted, #6b7280);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}

.fp {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
  user-select: all;
}

.link-btn {
  background: transparent;
  border: none;
  color: var(--accent, #2563eb);
  cursor: pointer;
  font-size: 12px;
  padding: 2px 6px;
}
.link-btn:hover { text-decoration: underline; }

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot-green { background: #22c55e; }
.dot-amber { background: #f59e0b; }
.dot-gray  { background: #9ca3af; }
.dot-red   { background: #ef4444; }

.live-indicator {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}
.pulsing {
  animation: pulse 1.6s ease-in-out infinite;
  box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16);
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16); }
  50%      { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.04); }
}
</style>
