<script setup lang="ts">
// FindingsPanel —— 漏洞工单列表 + 看板视图（PR-S26）。
//
// 视图模式：
//   - 列表：filter by status/severity/keyword
//   - 看板：5 状态列；点卡片 → 详情
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';

import { findingClient, tenancyClient } from '@/api/transport';
import { downloadExport, type ExportFormat } from '@/api/export';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { Finding } from '@/gen/proto/redmatrix/finding/v1/finding_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const STATUSES = ['open', 'triaged', 'confirmed', 'fixed', 'false_positive'] as const;
const STATUS_LABELS: Record<string, string> = {
  open: '待处理',
  triaged: '已分派',
  confirmed: '已确认',
  fixed: '已修复',
  false_positive: '误报',
};
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

const toast = useToast();
const router = useRouter();

const mode = ref<'list' | 'kanban'>('list');
const findings = ref<Finding[]>([]);
const total = ref(0);
const projects = ref<Project[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());

const filterProjectId = ref('');
const filterStatus = ref('');
const filterSeverity = ref('');
const filterMinSeverity = ref('');
const filterKeyword = ref('');
const exporting = ref(false);

async function loadProjects() {
  try {
    const r = await tenancyClient.listProjects({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 100 });
    projects.value = r.projects;
  } catch {
    // 忽略
  }
}

async function refresh() {
  loading.value = true;
  try {
    const r = await findingClient.listFindings({
      projectId: filterProjectId.value || undefined,
      status: filterStatus.value || undefined,
      severity: filterSeverity.value || undefined,
      minSeverity: filterMinSeverity.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: 1,
      pageSize: 200,
    });
    findings.value = r.findings;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  await Promise.all([loadProjects(), refresh()]);
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

const byStatus = computed(() => {
  const m: Record<string, Finding[]> = {};
  for (const s of STATUSES) m[s] = [];
  for (const f of findings.value) {
    (m[f.status] ||= []).push(f);
  }
  return m;
});

function severityBadge(s: string) {
  switch (s) {
    case 'critical': return 'red';
    case 'high':     return 'amber';
    case 'medium':   return 'amber';
    case 'low':      return '';
    case 'info':     return '';
    default:         return '';
  }
}

function statusBadge(s: string) {
  switch (s) {
    case 'open':           return 'blue';
    case 'triaged':        return 'amber';
    case 'confirmed':      return 'red';
    case 'fixed':          return 'green';
    case 'false_positive': return '';
    default:               return '';
  }
}

function statusLabel(s: string) {
  return STATUS_LABELS[s] || s;
}

function open(f: Finding) {
  router.push({ name: 'finding-detail', params: { id: f.id } });
}

// PR-S65：按当前 filter 触发下载。
async function exportAs(format: ExportFormat) {
  if (exporting.value) return;
  exporting.value = true;
  try {
    await downloadExport('findings', format, {
      project_id: filterProjectId.value || undefined,
      status: filterStatus.value || undefined,
      severity: filterSeverity.value || undefined,
      min_severity: filterMinSeverity.value || undefined,
      keyword: filterKeyword.value || undefined,
    });
    toast.success(`已导出 ${format.toUpperCase()}`);
  } catch (e) {
    toast.error(`导出失败：${errorMessage(e)}`);
  } finally {
    exporting.value = false;
  }
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>漏洞工单</h2>
        <div class="tabs">
          <button :class="{ active: mode === 'list' }" @click="mode = 'list'">列表</button>
          <button :class="{ active: mode === 'kanban' }" @click="mode = 'kanban'">看板</button>
        </div>
      </div>

      <div class="row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px">
        <select v-model="filterProjectId" :disabled="loading">
          <option value="">所有项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option v-for="s in STATUSES" :key="s" :value="s">{{ statusLabel(s) }}</option>
        </select>
        <select v-model="filterSeverity" :disabled="loading">
          <option value="">所有严重度</option>
          <option v-for="s in SEVERITIES" :key="s" :value="s">{{ s }}</option>
        </select>
        <select v-model="filterMinSeverity" :disabled="loading">
          <option value="">最低严重度</option>
          <option value="high">≥ high</option>
          <option value="critical">= critical</option>
        </select>
        <input v-model="filterKeyword" placeholder="title / host 模糊" :disabled="loading" style="width: 200px" />
        <button :disabled="loading" @click="refresh()">查询</button>
        <span class="export-sep" aria-hidden="true">|</span>
        <span class="muted" style="align-self: center">导出</span>
        <button :disabled="loading || exporting" @click="exportAs('csv')">CSV</button>
        <button :disabled="loading || exporting" @click="exportAs('json')">JSON</button>
        <button :disabled="loading || exporting" @click="exportAs('xlsx')">Excel</button>
        <span class="muted" style="margin-left: auto">{{ total }} 条</span>
      </div>
    </div>

    <!-- 列表 -->
    <div v-if="mode === 'list'" class="card">
      <table v-if="findings.length > 0">
        <thead>
          <tr>
            <th>严重度</th>
            <th>状态</th>
            <th>标题</th>
            <th>host</th>
            <th>项目</th>
            <th>命中</th>
            <th>最近一次</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in findings" :key="f.id" @click="open(f)" class="row-clickable">
            <td><span class="badge" :class="severityBadge(f.severity)">{{ f.severity }}</span></td>
            <td><span class="badge" :class="statusBadge(f.status)">{{ statusLabel(f.status) }}</span></td>
            <td>{{ f.title }}</td>
            <td class="muted">{{ f.host }}</td>
            <td class="muted">{{ projectName.get(f.projectId) || f.projectId.slice(0, 8) }}</td>
            <td class="muted">{{ f.occurrenceCount }}</td>
            <td class="muted" :title="formatAbsoluteTime(f.lastSeenAt)">
              {{ formatRelativeTime(f.lastSeenAt, nowTick) }}
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted" style="text-align: center; padding: 24px">
        暂无漏洞工单。nuclei 扫到高危 → 自动落表。
      </p>
    </div>

    <!-- 看板 -->
    <div v-else class="kanban">
      <div v-for="s in STATUSES" :key="s" class="kanban-col">
        <h3>
          <span class="badge" :class="statusBadge(s)">{{ statusLabel(s) }}</span>
          <span class="muted" style="font-size: 12px; margin-left: 6px">{{ byStatus[s].length }}</span>
        </h3>
        <div class="kanban-list">
          <div v-for="f in byStatus[s]" :key="f.id" class="kanban-card" @click="open(f)">
            <div class="row" style="align-items: center; gap: 6px">
              <span class="badge" :class="severityBadge(f.severity)">{{ f.severity }}</span>
              <span class="muted" style="font-size: 11px">×{{ f.occurrenceCount }}</span>
            </div>
            <div class="kanban-title">{{ f.title }}</div>
            <div class="muted kanban-host">{{ f.host }}</div>
          </div>
          <p v-if="byStatus[s].length === 0" class="muted" style="text-align: center; font-size: 12px; padding: 16px 0">
            无
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.page { display: flex; flex-direction: column; gap: 16px; }
.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.muted { color: var(--muted, #6b7280); }
.tabs { display: inline-flex; gap: 4px; }
.tabs button {
  background: transparent;
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 6px;
  padding: 4px 10px;
  font-size: 13px;
  cursor: pointer;
}
.tabs button.active {
  background: var(--accent, #2563eb);
  color: #fff;
  border-color: var(--accent, #2563eb);
}
.row-clickable { cursor: pointer; }
.row-clickable:hover { background: rgba(59, 130, 246, 0.04); }
.badge.blue { background: rgba(59, 130, 246, 0.16); color: #1d4ed8; }
.badge.green { background: rgba(22, 163, 74, 0.16); color: #166534; }
.badge.amber { background: rgba(245, 158, 11, 0.16); color: #92400e; }
.badge.red { background: rgba(239, 68, 68, 0.16); color: #991b1b; }
.kanban {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}
.kanban-col {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 10px;
  display: flex;
  flex-direction: column;
}
.kanban-col h3 {
  margin: 0 0 8px;
  font-size: 13px;
}
.kanban-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-height: 200px;
  max-height: calc(100vh - 280px);
  overflow-y: auto;
}
.kanban-card {
  background: var(--surface-alt, #f8fafc);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 6px;
  padding: 8px;
  cursor: pointer;
  font-size: 12px;
}
.kanban-card:hover { background: rgba(59, 130, 246, 0.04); }
.kanban-title {
  margin-top: 4px;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.kanban-host {
  font-size: 11px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.export-sep { color: var(--border, #e2e8f0); align-self: center; padding: 0 4px; }
</style>
