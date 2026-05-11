<script setup lang="ts">
// ScansPanel —— 扫描任务列表 + 创建（PR-S1）。
//
// 范围：仅 Task CRUD；不含调度 / Agent 拉任务 / 结果上报（后续 PR）。
import { ref, computed, onMounted, onUnmounted } from 'vue';

import { scanClient, tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { ScanTask } from '@/gen/proto/redmatrix/scan/v1/scan_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const REFRESH_INTERVAL_MS = 30_000;

const toast = useToast();

const tasks = ref<ScanTask[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const filterStatus = ref('');
const filterKeyword = ref('');
const filterProjectId = ref('');
const loading = ref(false);

const projects = ref<Project[]>([]);
const nowTick = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

async function refresh() {
  loading.value = true;
  try {
    const r = await scanClient.listScanTasks({
      projectId: filterProjectId.value || undefined,
      status: filterStatus.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    tasks.value = r.tasks;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

async function loadProjects() {
  try {
    const r = await tenancyClient.listProjects({
      tenantId: DEFAULT_TENANT_ID,
      page: 1,
      pageSize: 100,
    });
    projects.value = r.projects;
  } catch {
    // 忽略；CreateModal 用 projectId 输入框兜底
  }
}

onMounted(() => {
  loadProjects();
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

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

// === 创建 ===
const showCreate = ref(false);
const newT = ref({
  projectId: '',
  name: '',
  kind: 'port_scan',
  target: '',
  targetKind: 'host',
});
const submitting = ref(false);

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  try {
    await scanClient.createScanTask({
      projectId: newT.value.projectId,
      name: newT.value.name,
      kind: newT.value.kind,
      target: newT.value.target,
      targetKind: newT.value.targetKind,
    });
    toast.success(`任务 ${newT.value.name} 已创建（pending）`);
    showCreate.value = false;
    newT.value = { projectId: '', name: '', kind: 'port_scan', target: '', targetKind: 'host' };
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function cancel(id: string, name: string) {
  if (!confirm(`取消任务 ${name}？`)) return;
  try {
    await scanClient.cancelScanTask({ id });
    toast.warning(`任务 ${name} 已取消`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function del(id: string, name: string) {
  if (!confirm(`删除任务 ${name}？软删，名称可重用。`)) return;
  try {
    await scanClient.deleteScanTask({ id });
    toast.success(`任务 ${name} 已删除`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

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
function kindLabel(k: string) {
  switch (k) {
    case 'port_scan':   return '端口扫描';
    case 'web_crawl':   return '网页爬取';
    case 'subdomain':   return '子域名';
    case 'fingerprint': return '指纹识别';
    case 'vuln_scan':   return '漏洞扫描';
    default:            return k;
  }
}
function targetKindLabel(k: string) {
  switch (k) {
    case 'host': return '域名';
    case 'ip':   return 'IP';
    case 'cidr': return 'CIDR';
    case 'url':  return 'URL';
    default:     return k;
  }
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>扫描任务</h2>
        <span class="muted live-indicator" :title="`每 ${REFRESH_INTERVAL_MS / 1000}s 自动刷新`">
          <span class="dot dot-green pulsing" v-if="!loading" />
          <span class="dot dot-amber" v-else />
          实时 · {{ REFRESH_INTERVAL_MS / 1000 }}s
        </span>
      </div>

      <div class="row" style="flex-wrap: wrap; gap: 8px">
        <select v-model="filterProjectId" :disabled="loading">
          <option value="">所有项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option value="pending">pending</option>
          <option value="running">running</option>
          <option value="completed">completed</option>
          <option value="failed">failed</option>
          <option value="canceled">canceled</option>
        </select>
        <input
          v-model="filterKeyword"
          placeholder="按任务名模糊搜索"
          :disabled="loading"
          style="width: 240px"
        />
        <button :disabled="loading" @click="page = 1; refresh()">查询</button>
        <button class="primary" @click="showCreate = true">新建任务</button>
      </div>

      <table>
        <thead>
          <tr>
            <th>任务名</th>
            <th>项目</th>
            <th>类型</th>
            <th>目标</th>
            <th>状态</th>
            <th>创建</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tasks" :key="t.id">
            <td>
              <router-link :to="`/scans/${t.id}`" class="task-link">{{ t.name }}</router-link>
            </td>
            <td class="muted">{{ projectName.get(t.projectId) || t.projectId.slice(0, 8) }}</td>
            <td>
              <span class="chip">{{ kindLabel(t.kind) }}</span>
            </td>
            <td>
              <code class="target">{{ t.target }}</code>
              <span class="muted target-kind">{{ targetKindLabel(t.targetKind) }}</span>
            </td>
            <td>
              <span class="badge" :class="statusBadge(t.status)">{{ t.status }}</span>
            </td>
            <td class="muted" :title="formatAbsoluteTime(t.createdAt)">
              {{ formatRelativeTime(t.createdAt, nowTick) }}
            </td>
            <td>
              <div class="row" style="gap: 4px">
                <button
                  v-if="t.status === 'pending' || t.status === 'running'"
                  @click="cancel(t.id, t.name)"
                >取消</button>
                <button
                  v-if="authStore.isSuperAdmin() || authStore.isAuditor()"
                  class="danger"
                  @click="del(t.id, t.name)"
                >删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="tasks.length === 0">
            <td colspan="7" class="muted" style="text-align: center; padding: 24px">
              暂无任务。新建一个开始扫描。
            </td>
          </tr>
        </tbody>
      </table>

      <div class="row" style="justify-content: space-between">
        <span class="muted">共 {{ total }} 个任务</span>
        <div class="row">
          <button :disabled="page <= 1 || loading" @click="page--; refresh()">上一页</button>
          <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
          <button :disabled="page >= totalPages() || loading" @click="page++; refresh()">下一页</button>
        </div>
      </div>
    </div>

    <!-- Create modal -->
    <div v-if="showCreate" class="modal-mask">
      <div class="card modal">
        <h2>新建扫描任务</h2>

        <div class="form">
          <div class="form-row">
            <span class="label">项目</span>
            <select v-model="newT.projectId" :disabled="submitting" style="flex: 1">
              <option value="" disabled>请选择项目</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>

          <div class="form-row">
            <span class="label">任务名</span>
            <input v-model="newT.name" placeholder="如 prod-web-octobre" :disabled="submitting" style="flex: 1" />
          </div>

          <div class="form-row">
            <span class="label">类型</span>
            <select v-model="newT.kind" :disabled="submitting" style="flex: 1">
              <option value="port_scan">端口扫描 (port_scan)</option>
              <option value="web_crawl">网页爬取 (web_crawl)</option>
              <option value="subdomain">子域名 (subdomain)</option>
              <option value="fingerprint">指纹识别 (fingerprint)</option>
              <option value="vuln_scan">漏洞扫描 (vuln_scan)</option>
            </select>
          </div>

          <div class="form-row">
            <span class="label">目标类型</span>
            <select v-model="newT.targetKind" :disabled="submitting" style="flex: 1">
              <option value="host">域名 (host)</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="url">URL</option>
            </select>
          </div>

          <div class="form-row">
            <span class="label">目标</span>
            <input v-model="newT.target" placeholder="如 example.com / 192.168.1.0/24" :disabled="submitting" style="flex: 1" />
          </div>

          <p class="muted">
            创建后状态为 pending；调度逻辑（PR-S2）落地后自动派发到项目允许的 online 节点。
          </p>

          <div class="row">
            <button
              class="primary"
              :disabled="submitting || !newT.projectId || !newT.name || !newT.target"
              @click="create"
            >
              {{ submitting ? '创建中…' : '创建' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}

.muted { color: var(--muted, #6b7280); }

.live-indicator {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}
.dot-green { background: #22c55e; }
.dot-amber { background: #f59e0b; }

.pulsing {
  animation: pulse 1.6s ease-in-out infinite;
  box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16);
}
@keyframes pulse {
  0%, 100% { box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.16); }
  50%      { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.04); }
}

.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}

.target { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.target-kind { font-size: 11px; margin-left: 6px; }

/* 给 status badge 加 blue 颜色支持（其它颜色复用全局 styles.css 的 .green/.amber/.red）*/
.badge.blue {
  background: rgba(59, 130, 246, 0.16);
  color: #1d4ed8;
}

.task-link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.task-link:hover {
  text-decoration: underline;
}

.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.36);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal {
  width: min(520px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}

.form { display: flex; flex-direction: column; gap: 12px; margin-top: 8px; }
.form-row { display: flex; align-items: center; gap: 12px; }
.label { width: 80px; color: var(--muted, #6b7280); font-size: 13px; }
</style>
