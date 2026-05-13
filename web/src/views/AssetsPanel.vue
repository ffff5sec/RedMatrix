<script setup lang="ts">
// AssetsPanel —— 资产视图列表（PR-S8）。
//
// 资产 = scan_results 派生的去重视图（host / subdomain / url）；按 last_seen
// 降序，支持 kind tab 切换 + 关键字 + 项目过滤 + 分页。
import { ref, computed, onMounted, onUnmounted } from 'vue';

import { assetClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { Asset } from '@/gen/proto/redmatrix/asset/v1/asset_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const toast = useToast();

const assets = ref<Asset[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(50);
const loading = ref(false);

const filterKind = ref<'' | 'host' | 'subdomain' | 'url'>('');
const filterProjectId = ref('');
const keyword = ref('');
const minAgeDays = ref(0); // 0 = 不过滤；7/30/90 等

const projects = ref<Project[]>([]);
const nowTick = ref(Date.now());
let tickTimer: ReturnType<typeof setInterval> | null = null;

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

async function refresh() {
  loading.value = true;
  try {
    const r = await assetClient.listAssets({
      kind: filterKind.value || undefined,
      projectId: filterProjectId.value || undefined,
      keyword: keyword.value || undefined,
      minAgeDays: minAgeDays.value > 0 ? minAgeDays.value : undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    assets.value = r.assets;
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
    // 忽略；项目过滤可手输 ID
  }
}

onMounted(() => {
  loadProjects();
  refresh();
  tickTimer = setInterval(() => { nowTick.value = Date.now(); }, 1_000);
});
onUnmounted(() => {
  if (tickTimer) clearInterval(tickTimer);
});

function applyFilters() {
  page.value = 1;
  refresh();
}

function pickKind(k: '' | 'host' | 'subdomain' | 'url') {
  filterKind.value = k;
  applyFilters();
}

function kindLabel(k: string) {
  switch (k) {
    case 'host': return '主机';
    case 'subdomain': return '子域名';
    case 'url': return 'URL';
    default: return k;
  }
}

// PR-S31 freshness: 距 lastSeen 多少天
function daysSinceLastSeen(lastSeen?: { seconds: bigint } | null): number {
  if (!lastSeen) return 0;
  const ms = Number(lastSeen.seconds) * 1000;
  return Math.floor((nowTick.value - ms) / 86_400_000);
}

// 高于 30 天 → stale；高于 90 天 → very stale
function staleLevel(lastSeen?: { seconds: bigint } | null): '' | 'stale' | 'very-stale' {
  const d = daysSinceLastSeen(lastSeen);
  if (d >= 90) return 'very-stale';
  if (d >= 30) return 'stale';
  return '';
}
</script>

<template>
  <div class="page">
    <div class="header">
      <h2 style="margin: 0">资产视图</h2>
      <span class="muted">从扫描结果派生：同一资产去重，result_count 累计；按最近活跃排序。</span>
    </div>

    <div class="card">
      <div class="row" style="gap: 8px; flex-wrap: wrap; margin-bottom: 12px">
        <button
          :class="{ tab: true, 'tab-active': filterKind === '' }"
          @click="pickKind('')"
        >全部</button>
        <button
          :class="{ tab: true, 'tab-active': filterKind === 'host' }"
          @click="pickKind('host')"
        >主机</button>
        <button
          :class="{ tab: true, 'tab-active': filterKind === 'subdomain' }"
          @click="pickKind('subdomain')"
        >子域名</button>
        <button
          :class="{ tab: true, 'tab-active': filterKind === 'url' }"
          @click="pickKind('url')"
        >URL</button>
      </div>

      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input
          v-model="keyword"
          placeholder="value 关键字（模糊匹配）"
          :disabled="loading"
          style="flex: 1; min-width: 220px"
          @keydown.enter="applyFilters"
        />
        <select v-model="filterProjectId" :disabled="loading">
          <option value="">全部项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <select v-model.number="minAgeDays" :disabled="loading" title="资产新鲜度过滤">
          <option :value="0">全部新鲜度</option>
          <option :value="7">≥ 7 天未扫</option>
          <option :value="30">≥ 30 天未扫</option>
          <option :value="90">≥ 90 天未扫</option>
        </select>
        <button :disabled="loading" @click="applyFilters">查询</button>
      </div>
    </div>

    <div class="card">
      <table>
        <thead>
          <tr>
            <th style="width: 90px">类型</th>
            <th>值</th>
            <th style="width: 120px">项目</th>
            <th style="width: 80px">命中</th>
            <th style="width: 140px">最近</th>
            <th style="width: 140px">首发</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="a in assets" :key="a.id" :class="staleLevel(a.lastSeen)">
            <td><span class="chip">{{ kindLabel(a.kind) }}</span></td>
            <td>
              <router-link :to="`/assets/${a.id}`" class="link">
                <code class="value">{{ a.value }}</code>
              </router-link>
            </td>
            <td class="muted">{{ projectName.get(a.projectId) || a.projectId.slice(0, 8) }}</td>
            <td>{{ a.resultCount }}</td>
            <td class="muted" :title="formatAbsoluteTime(a.lastSeen)">
              {{ formatRelativeTime(a.lastSeen, nowTick) }}
              <span v-if="staleLevel(a.lastSeen)" class="stale-badge" :class="staleLevel(a.lastSeen)">
                {{ daysSinceLastSeen(a.lastSeen) }}d
              </span>
            </td>
            <td class="muted" :title="formatAbsoluteTime(a.firstSeen)">
              {{ formatRelativeTime(a.firstSeen, nowTick) }}
            </td>
          </tr>
          <tr v-if="assets.length === 0 && !loading">
            <td colspan="6" class="muted" style="text-align: center; padding: 24px">
              暂无资产。运行扫描任务以派生结果。
            </td>
          </tr>
          <tr v-if="loading">
            <td colspan="6" class="muted" style="text-align: center; padding: 24px">加载中…</td>
          </tr>
        </tbody>
      </table>

      <div class="row" style="justify-content: space-between; margin-top: 12px">
        <span class="muted">共 {{ total }} 个资产</span>
        <div class="row">
          <button :disabled="page <= 1 || loading" @click="page--; refresh()">上一页</button>
          <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
          <button :disabled="page >= totalPages() || loading" @click="page++; refresh()">下一页</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.page { display: flex; flex-direction: column; gap: 16px; }
.header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.muted { color: var(--muted, #6b7280); }

.tab {
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 13px;
}
.tab-active {
  background: rgba(59, 130, 246, 0.16);
  color: #1d4ed8;
  font-weight: 500;
}

.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}

.value {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 13px;
  word-break: break-all;
}

.link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.link:hover { text-decoration: underline; }
/* PR-S31 freshness 染色 */
tr.stale { background: rgba(245, 158, 11, 0.06); }
tr.very-stale { background: rgba(239, 68, 68, 0.08); }
.stale-badge {
  display: inline-block;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-family: ui-monospace, SFMono-Regular, monospace;
  margin-left: 6px;
}
.stale-badge.stale { background: rgba(245, 158, 11, 0.18); color: #92400e; }
.stale-badge.very-stale { background: rgba(239, 68, 68, 0.18); color: #991b1b; }
</style>
