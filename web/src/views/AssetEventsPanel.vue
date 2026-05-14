<script setup lang="ts">
// AssetEventsPanel —— 资产变更事件时间线（PR-S58 / SPEC §2.7）。
//
// 范式与 AuditPanel 类似：表格 + filter（kind / project / 时间）+ 展开 payload。
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { Timestamp } from '@bufbuild/protobuf';

import { assetClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { AssetEvent } from '@/gen/proto/redmatrix/asset/v1/asset_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const toast = useToast();

const events = ref<AssetEvent[]>([]);
const total = ref(0);
const loading = ref(false);
const nowTick = ref(Date.now());
const filterKind = ref('');
const filterProjectId = ref('');
const filterTimeFrom = ref('');
const filterTimeTo = ref('');
const expanded = ref<Record<string, boolean>>({});
const projects = ref<Project[]>([]);
const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

// PR-S57 一期 5 类（消失/证书到期 PR-S5x 后端写）
const KIND_OPTIONS = [
  { value: '', label: '所有事件' },
  { value: 'asset_new_subdomain', label: '新增子域名' },
  { value: 'asset_new_port', label: '新主机端口' },
  { value: 'asset_new_service', label: '新服务' },
  { value: 'asset_disappeared', label: '资产消失' },
  { value: 'cert_expiring_soon', label: '证书即将到期' },
];

async function loadProjects() {
  try {
    const r = await tenancyClient.listProjects({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 100 });
    projects.value = r.projects;
  } catch (e) {
    toast.warning('项目列表加载失败：' + errorMessage(e));
  }
}

async function refresh() {
  loading.value = true;
  try {
    const r = await assetClient.listAssetEvents({
      eventKind: filterKind.value || undefined,
      projectId: filterProjectId.value || undefined,
      timeFrom: filterTimeFrom.value
        ? Timestamp.fromDate(new Date(filterTimeFrom.value))
        : undefined,
      timeTo: filterTimeTo.value
        ? Timestamp.fromDate(new Date(filterTimeTo.value))
        : undefined,
      page: 1,
      pageSize: 100,
    });
    events.value = r.events;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

let tickTimer: ReturnType<typeof setInterval> | null = null;
onMounted(async () => {
  await Promise.all([loadProjects(), refresh()]);
  tickTimer = setInterval(() => (nowTick.value = Date.now()), 1000);
});
onUnmounted(() => {
  if (tickTimer !== null) {
    clearInterval(tickTimer);
    tickTimer = null;
  }
});

function toggleExpand(id: string) {
  expanded.value[id] = !expanded.value[id];
}

function parsePayload(s: string): Record<string, unknown> {
  if (!s) return {};
  try {
    return JSON.parse(s);
  } catch {
    return {};
  }
}

function payloadPretty(s: string): string {
  return JSON.stringify(parsePayload(s), null, 2);
}

function kindLabel(k: string): string {
  const opt = KIND_OPTIONS.find((o) => o.value === k);
  return opt ? opt.label : k;
}

function kindBadge(k: string): string {
  if (k === 'asset_disappeared') return 'red';
  if (k === 'cert_expiring_soon') return 'amber';
  return 'blue';
}

function assetTitle(e: AssetEvent): string {
  const p = parsePayload(e.payloadJson);
  const v = typeof p.asset_value === 'string' ? p.asset_value : '';
  return v || '—';
}
</script>

<template>
  <div class="page">
    <div class="card">
      <h2>资产变更时间线</h2>
      <p class="muted">
        SPEC §2.7 一期：新增子域名 / 新主机端口 / 新服务 / 资产消失 / 证书即将到期。
        前 3 类由 ReportResults 派生；消失类和证书到期由后台扫扫触发。
      </p>

      <div class="row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px">
        <select v-model="filterKind" :disabled="loading" style="width: 180px">
          <option v-for="opt in KIND_OPTIONS" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
        </select>
        <select v-model="filterProjectId" :disabled="loading" style="width: 220px">
          <option value="">所有项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <label class="muted" style="font-size: 12px">起：
          <input v-model="filterTimeFrom" type="datetime-local" :disabled="loading" />
        </label>
        <label class="muted" style="font-size: 12px">止：
          <input v-model="filterTimeTo" type="datetime-local" :disabled="loading" />
        </label>
        <button :disabled="loading" @click="refresh()">查询</button>
        <span class="muted" style="margin-left: auto">{{ total }} 条</span>
      </div>
    </div>

    <div class="card">
      <table v-if="events.length > 0">
        <thead>
          <tr>
            <th style="width: 16px"></th>
            <th>时间</th>
            <th>事件</th>
            <th>资产值</th>
            <th>项目</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="e in events" :key="e.id">
            <tr @click="toggleExpand(e.id)" style="cursor: pointer">
              <td>{{ expanded[e.id] ? '▾' : '▸' }}</td>
              <td class="muted" :title="formatAbsoluteTime(e.createdAt)">
                {{ formatRelativeTime(e.createdAt, nowTick) }}
              </td>
              <td><span class="badge" :class="kindBadge(e.eventKind)">{{ kindLabel(e.eventKind) }}</span></td>
              <td><code>{{ assetTitle(e) }}</code></td>
              <td class="muted">
                <span v-if="e.projectId">{{ projectName.get(e.projectId) || e.projectId.slice(0, 8) }}</span>
                <span v-else>—</span>
              </td>
            </tr>
            <tr v-if="expanded[e.id]" class="expand-row">
              <td></td>
              <td colspan="4">
                <div class="kv-grid">
                  <div><span class="muted">id</span><code>{{ e.id }}</code></div>
                  <div><span class="muted">tenant_id</span><code>{{ e.tenantId }}</code></div>
                  <div v-if="e.assetId"><span class="muted">asset_id</span>
                    <router-link :to="`/assets/${e.assetId}`"><code>{{ e.assetId }}</code></router-link>
                  </div>
                </div>
                <h4 style="margin: 12px 0 4px">payload</h4>
                <pre class="payload-block">{{ payloadPretty(e.payloadJson) }}</pre>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      <p v-else class="muted" style="text-align: center; padding: 24px">
        暂无资产事件。运行一次扫描任务 → 新发现的资产会派 new_* 事件。
      </p>
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
.badge.blue { background: rgba(59, 130, 246, 0.16); color: #1d4ed8; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-family: ui-monospace, SFMono-Regular, monospace; }
.badge.amber { background: rgba(245, 158, 11, 0.16); color: #92400e; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-family: ui-monospace, SFMono-Regular, monospace; }
.badge.red { background: rgba(239, 68, 68, 0.16); color: #991b1b; padding: 1px 8px; border-radius: 4px; font-size: 11px; font-family: ui-monospace, SFMono-Regular, monospace; }
.expand-row { background: var(--surface-alt, #f8fafc); }
.kv-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 6px 16px;
  font-size: 12px;
}
.kv-grid > div { display: flex; gap: 8px; align-items: baseline; }
.kv-grid .muted { min-width: 90px; }
.payload-block {
  background: #0f172a;
  color: #e2e8f0;
  padding: 12px;
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
  white-space: pre;
  overflow-x: auto;
  margin: 0;
}
</style>
