<script setup lang="ts">
// ScanDetail —— 扫描任务详情页（PR-S2）。
// 路由：/scans/:id
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { scanClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type {
  ScanTask,
  TaskAssignment,
  ScanResult,
} from '@/gen/proto/redmatrix/scan/v1/scan_pb';
import type { Node, Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const REFRESH_INTERVAL_MS = 30_000;
const route = useRoute();
const router = useRouter();
const toast = useToast();

const taskId = computed(() => String(route.params.id));
const task = ref<ScanTask | null>(null);
const project = ref<Project | null>(null);
const assignments = ref<TaskAssignment[]>([]);
const results = ref<ScanResult[]>([]);
const nodes = ref<Map<string, Node>>(new Map());
const loading = ref(false);
const nowTick = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

async function refresh() {
  if (!taskId.value) return;
  loading.value = true;
  try {
    const [t, a, r] = await Promise.all([
      scanClient.getScanTask({ id: taskId.value }),
      scanClient.listTaskAssignments({ taskId: taskId.value }),
      scanClient.listTaskResults({ taskId: taskId.value }),
    ]);
    task.value = t.task ?? null;
    assignments.value = a.assignments;
    results.value = r.results;

    // 顺手拉项目 + 涉及到的节点详情（节点名 / 状态）
    if (task.value?.projectId) {
      const p = await tenancyClient.getProject({ id: task.value.projectId });
      project.value = p.project ?? null;
    }
    if (assignments.value.length > 0) {
      // 简单方案：拉租户全节点缓存（节点 < 100）；后续可加 GetNodesByIDs
      const ns = await tenancyClient.listNodes({
        tenantId: task.value?.tenantId || '',
        page: 1,
        pageSize: 200,
      });
      const m = new Map<string, Node>();
      for (const n of ns.nodes) m.set(n.id, n);
      nodes.value = m;
    }
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
    case 'pending':   return 'amber';
    case 'running':   return 'blue';
    case 'completed': return 'green';
    case 'failed':    return 'red';
    case 'canceled':  return '';
    default:          return '';
  }
}
function assignmentBadge(s: string) {
  switch (s) {
    case 'assigned':  return 'amber';
    case 'pulled':    return 'blue';
    case 'running':   return 'blue';
    case 'completed': return 'green';
    case 'failed':    return 'red';
    default:          return '';
  }
}
function kindLabel(k: string) {
  switch (k) {
    case 'port_scan':   return '端口扫描';
    case 'web_crawl':   return '网页爬取';
    case 'subdomain':   return '子域名';
    case 'fingerprint': return '指纹识别';
    default:            return k;
  }
}
function nodeName(id: string) {
  return nodes.value.get(id)?.name || id.slice(0, 8);
}

// formatData 把 schema-less Struct 渲染成简洁 KV 字串。
function formatData(s: unknown): string {
  if (!s) return '–';
  let obj: Record<string, unknown>;
  // protobuf Struct 在 connect-es 反序列化为 { fields, getType, toJson... }
  // 简单处理：toJson() 取纯对象，再格式化
  if (typeof (s as { toJson?: () => unknown }).toJson === 'function') {
    obj = (s as { toJson: () => Record<string, unknown> }).toJson();
  } else {
    obj = s as Record<string, unknown>;
  }
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join('  ');
}
function nodeStatus(id: string) {
  return nodes.value.get(id)?.status || '?';
}

async function cancel() {
  if (!task.value) return;
  if (!confirm(`取消任务 ${task.value.name}？`)) return;
  try {
    await scanClient.cancelScanTask({ id: task.value.id });
    toast.warning(`任务 ${task.value.name} 已取消`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
async function del() {
  if (!task.value) return;
  if (!confirm(`删除任务 ${task.value.name}？软删，可重用名称。`)) return;
  try {
    await scanClient.deleteScanTask({ id: task.value.id });
    toast.success(`任务 ${task.value.name} 已删除`);
    router.push('/scans');
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
</script>

<template>
  <div class="detail">
    <div class="head">
      <button class="back" @click="router.push('/scans')">← 返回</button>
      <span class="muted live-indicator">
        <span class="dot dot-green pulsing" v-if="!loading" />
        <span class="dot dot-amber" v-else />
        实时 · {{ REFRESH_INTERVAL_MS / 1000 }}s
      </span>
    </div>

    <div v-if="!task && !loading" class="card empty">
      <p>任务不存在或已删除。</p>
      <button @click="router.push('/scans')">返回</button>
    </div>

    <template v-if="task">
      <div class="card">
        <div class="row" style="justify-content: space-between; align-items: flex-start">
          <div>
            <h1 class="title">{{ task.name }}</h1>
            <div class="row meta-row">
              <span class="badge" :class="statusBadge(task.status)">{{ task.status }}</span>
              <span class="chip">{{ kindLabel(task.kind) }}</span>
              <span class="muted">·</span>
              <span class="muted">
                <code>{{ task.target }}</code>
                <span class="target-kind">{{ task.targetKind }}</span>
              </span>
            </div>
          </div>
          <div class="row" style="gap: 8px">
            <button v-if="task.status === 'pending' || task.status === 'running'" @click="cancel">
              取消任务
            </button>
            <button class="danger" @click="del">删除</button>
          </div>
        </div>

        <div class="kv">
          <div class="kv-row"><span class="kv-k">ID</span><code>{{ task.id }}</code></div>
          <div class="kv-row">
            <span class="kv-k">项目</span>
            <span>
              <router-link v-if="project" :to="`/projects`" class="link">
                {{ project.name }}
              </router-link>
              <code v-else>{{ task.projectId }}</code>
            </span>
          </div>
          <div class="kv-row" v-if="task.createdAt">
            <span class="kv-k">创建</span>
            <span :title="formatAbsoluteTime(task.createdAt)">
              {{ formatAbsoluteTime(task.createdAt) }}（{{ formatRelativeTime(task.createdAt, nowTick) }}）
            </span>
          </div>
        </div>
      </div>

      <div class="card">
        <h2>派发单 <span class="muted">（{{ assignments.length }}）</span></h2>
        <p class="muted">
          创建时按项目 allowed_nodes ∩ tenant 在线节点派发。终态后不再变（PR-S3 起 Agent 拉取后会推进）。
        </p>
        <table v-if="assignments.length > 0">
          <thead>
            <tr>
              <th>节点</th>
              <th>节点状态</th>
              <th>派发状态</th>
              <th>派发时间</th>
              <th>开跑时间</th>
              <th>结束时间</th>
              <th>错误</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="a in assignments" :key="a.id">
              <td>
                <router-link :to="`/nodes/${a.nodeId}`" class="link">{{ nodeName(a.nodeId) }}</router-link>
              </td>
              <td>
                <span class="badge" :class="statusBadge(nodeStatus(a.nodeId))">{{ nodeStatus(a.nodeId) }}</span>
              </td>
              <td>
                <span class="badge" :class="assignmentBadge(a.status)">{{ a.status }}</span>
              </td>
              <td :title="formatAbsoluteTime(a.assignedAt)">
                {{ formatRelativeTime(a.assignedAt, nowTick) }}
              </td>
              <td>
                <span v-if="a.startedAt" :title="formatAbsoluteTime(a.startedAt)">
                  {{ formatRelativeTime(a.startedAt, nowTick) }}
                </span>
                <span v-else class="muted">–</span>
              </td>
              <td>
                <span v-if="a.finishedAt" :title="formatAbsoluteTime(a.finishedAt)">
                  {{ formatRelativeTime(a.finishedAt, nowTick) }}
                </span>
                <span v-else class="muted">–</span>
              </td>
              <td class="muted">{{ a.error || '–' }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted">
          0 派发。可能：项目未设白名单或白名单内节点全离线 / 项目尚未启用任何节点。
        </p>
      </div>

      <div class="card">
        <h2>扫描结果 <span class="muted">（{{ results.length }}）</span></h2>
        <p class="muted">
          Agent 完成任务后批量上报；按 task.kind 不同字段不同。MVP 用固定 mock 数据。
        </p>
        <table v-if="results.length > 0">
          <thead>
            <tr>
              <th>类型</th>
              <th>数据</th>
              <th>来源节点</th>
              <th>时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in results" :key="r.id">
              <td><span class="chip">{{ r.kind }}</span></td>
              <td>
                <code class="result-data">{{ formatData(r.data) }}</code>
              </td>
              <td>
                <router-link :to="`/nodes/${r.nodeId}`" class="link">{{ nodeName(r.nodeId) }}</router-link>
              </td>
              <td :title="formatAbsoluteTime(r.createdAt)">
                {{ formatRelativeTime(r.createdAt, nowTick) }}
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted">尚无结果。任务执行完后会出现。</p>
      </div>
    </template>
  </div>
</template>

<style scoped>
.detail { display: flex; flex-direction: column; gap: 16px; }
.head { display: flex; justify-content: space-between; align-items: center; }
.back {
  background: transparent; border: none; color: var(--accent, #2563eb);
  font-size: 13px; cursor: pointer; padding: 4px 0;
}
.back:hover { text-decoration: underline; }
.title { font-size: 22px; font-weight: 600; margin: 0 0 6px; }
.meta-row { align-items: center; gap: 8px; font-size: 13px; }
.muted { color: var(--muted, #6b7280); }
.target-kind { font-size: 11px; margin-left: 6px; color: var(--muted, #6b7280); }

.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.empty { text-align: center; padding: 48px 16px; }

.kv {
  margin-top: 16px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-top: 12px;
  border-top: 1px solid var(--border, #e2e8f0);
}
.kv-row { display: flex; align-items: center; gap: 12px; font-size: 13px; }
.kv-k { width: 80px; color: var(--muted, #6b7280); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }

.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}

.link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.link:hover { text-decoration: underline; }

.dot {
  display: inline-block; width: 8px; height: 8px; border-radius: 50%;
}
.dot-green { background: #22c55e; }
.dot-amber { background: #f59e0b; }

.live-indicator { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; }
.pulsing {
  animation: pulse 1.6s ease-in-out infinite;
  box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16);
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16); }
  50%      { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.04); }
}

.badge.blue {
  background: rgba(59, 130, 246, 0.16);
  color: #1d4ed8;
}

.result-data {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
  word-break: break-all;
  white-space: pre-wrap;
}
</style>
