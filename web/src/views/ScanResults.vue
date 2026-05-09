<script setup lang="ts">
// ScanResults —— 全局扫描结果搜索页（PR-S7）。
//
// 走 ScanService.SearchResults（ES 后端）。
//   - 顶部：关键字 + kind / project / node 过滤
//   - 中间：表格 + 分页
//   - 右侧：facet 边栏（kind / node 计数）
//
// 权限：后端 RBAC，前端不做收紧（PA 后端会注入 ProjectIDs 限制）。
import { ref, computed, onMounted, onUnmounted } from 'vue';

import { scanClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { ScanResult, Facet } from '@/gen/proto/redmatrix/scan/v1/scan_pb';
import type { Project, Node } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const toast = useToast();

const items = ref<ScanResult[]>([]);
const facets = ref<Facet[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(50);
const loading = ref(false);

// 过滤
const keyword = ref('');
const filterKind = ref('');
const filterProjectId = ref('');
const filterNodeId = ref('');

// projects / nodes 维表（用于过滤下拉 + 表格名字回填）
const projects = ref<Project[]>([]);
const nodes = ref<Node[]>([]);
const nowTick = ref(Date.now());
let tickTimer: ReturnType<typeof setInterval> | null = null;

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});
const nodeName = computed(() => {
  const m = new Map<string, string>();
  for (const n of nodes.value) m.set(n.id, n.name);
  return m;
});

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

async function search() {
  loading.value = true;
  try {
    const r = await scanClient.searchResults({
      keyword: keyword.value || undefined,
      kind: filterKind.value || undefined,
      projectId: filterProjectId.value || undefined,
      nodeId: filterNodeId.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    items.value = r.results;
    total.value = r.total;
    facets.value = r.facets;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

async function loadDimensions() {
  try {
    const [pr, nr] = await Promise.all([
      tenancyClient.listProjects({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 100 }),
      tenancyClient.listNodes({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 200 }),
    ]);
    projects.value = pr.projects;
    nodes.value = nr.nodes;
  } catch {
    // 忽略；过滤可手输 ID
  }
}

onMounted(() => {
  loadDimensions();
  search();
  tickTimer = setInterval(() => { nowTick.value = Date.now(); }, 1_000);
});
onUnmounted(() => {
  if (tickTimer) clearInterval(tickTimer);
});

function applyFilters() {
  page.value = 1;
  search();
}

function clearFilters() {
  keyword.value = '';
  filterKind.value = '';
  filterProjectId.value = '';
  filterNodeId.value = '';
  page.value = 1;
  search();
}

function onFacetClick(field: string, key: string) {
  if (field === 'kind') {
    filterKind.value = filterKind.value === key ? '' : key;
  } else if (field === 'node_id') {
    filterNodeId.value = filterNodeId.value === key ? '' : key;
  }
  applyFilters();
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

// formatData 把 Struct 渲染成简洁 KV 串（与 ScanDetail 同形）。
function formatData(s: unknown): string {
  if (!s) return '–';
  let obj: Record<string, unknown>;
  if (typeof (s as { toJson?: () => unknown }).toJson === 'function') {
    obj = (s as { toJson: () => Record<string, unknown> }).toJson();
  } else {
    obj = s as Record<string, unknown>;
  }
  return Object.entries(obj)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join('  ');
}

function facetBuckets(field: string) {
  const f = facets.value.find((x) => x.field === field);
  return f?.buckets ?? [];
}
</script>

<template>
  <div class="page">
    <div class="header">
      <h2 style="margin: 0">扫描结果搜索</h2>
      <span class="muted">基于 Elasticsearch 索引；关键字搜 host / port / banner / url / title 等字段。</span>
    </div>

    <div class="card">
      <div class="row" style="gap: 8px; flex-wrap: wrap">
        <input
          v-model="keyword"
          placeholder="关键字（host / banner / url ...）"
          :disabled="loading"
          style="flex: 1; min-width: 220px"
          @keydown.enter="applyFilters"
        />
        <select v-model="filterKind" :disabled="loading">
          <option value="">全部类型</option>
          <option value="port_scan">端口扫描</option>
          <option value="web_crawl">网页爬取</option>
          <option value="subdomain">子域名</option>
          <option value="fingerprint">指纹识别</option>
        </select>
        <select v-model="filterProjectId" :disabled="loading">
          <option value="">全部项目</option>
          <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
        </select>
        <select v-model="filterNodeId" :disabled="loading">
          <option value="">全部节点</option>
          <option v-for="n in nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
        </select>
        <button :disabled="loading" @click="applyFilters">查询</button>
        <button :disabled="loading" @click="clearFilters">清空</button>
      </div>
    </div>

    <div class="layout">
      <div class="card main">
        <table>
          <thead>
            <tr>
              <th style="width: 110px">类型</th>
              <th>数据</th>
              <th style="width: 140px">项目</th>
              <th style="width: 120px">节点</th>
              <th style="width: 120px">时间</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in items" :key="r.id">
              <td><span class="chip">{{ kindLabel(r.kind) }}</span></td>
              <td><code class="data">{{ formatData(r.data) }}</code></td>
              <td class="muted">{{ projectName.get(r.projectId) || r.projectId.slice(0, 8) }}</td>
              <td class="muted">
                <router-link
                  v-if="nodeName.get(r.nodeId)"
                  :to="`/nodes/${r.nodeId}`"
                  class="link"
                >
                  {{ nodeName.get(r.nodeId) }}
                </router-link>
                <span v-else>{{ r.nodeId.slice(0, 8) }}</span>
              </td>
              <td class="muted" :title="formatAbsoluteTime(r.createdAt)">
                {{ formatRelativeTime(r.createdAt, nowTick) }}
              </td>
            </tr>
            <tr v-if="items.length === 0 && !loading">
              <td colspan="5" class="muted" style="text-align: center; padding: 24px">
                暂无匹配结果。试试清空过滤或换关键字。
              </td>
            </tr>
            <tr v-if="loading">
              <td colspan="5" class="muted" style="text-align: center; padding: 24px">加载中…</td>
            </tr>
          </tbody>
        </table>

        <div class="row" style="justify-content: space-between; margin-top: 12px">
          <span class="muted">共 {{ total }} 条结果</span>
          <div class="row">
            <button :disabled="page <= 1 || loading" @click="page--; search()">上一页</button>
            <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
            <button :disabled="page >= totalPages() || loading" @click="page++; search()">下一页</button>
          </div>
        </div>
      </div>

      <div class="card facets">
        <h3 style="margin-top: 0">类型分布</h3>
        <ul class="facet-list">
          <li
            v-for="b in facetBuckets('kind')"
            :key="b.key"
            class="facet-item"
            :class="{ active: filterKind === b.key }"
            @click="onFacetClick('kind', b.key)"
          >
            <span>{{ kindLabel(b.key) }}</span>
            <span class="muted">{{ b.count }}</span>
          </li>
          <li v-if="facetBuckets('kind').length === 0" class="muted">暂无</li>
        </ul>

        <h3 style="margin-top: 16px">节点分布</h3>
        <ul class="facet-list">
          <li
            v-for="b in facetBuckets('node_id')"
            :key="b.key"
            class="facet-item"
            :class="{ active: filterNodeId === b.key }"
            @click="onFacetClick('node_id', b.key)"
          >
            <span>{{ nodeName.get(b.key) || b.key.slice(0, 8) }}</span>
            <span class="muted">{{ b.count }}</span>
          </li>
          <li v-if="facetBuckets('node_id').length === 0" class="muted">暂无</li>
        </ul>
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

.header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  flex-wrap: wrap;
}

.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}

.muted { color: var(--muted, #6b7280); }

.layout {
  display: grid;
  grid-template-columns: minmax(0, 1fr) 220px;
  gap: 16px;
}

.main { min-width: 0; }

.facets h3 {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
}

.facet-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.facet-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 4px 8px;
  border-radius: 4px;
  cursor: pointer;
  font-size: 13px;
}
.facet-item:hover {
  background: rgba(59, 130, 246, 0.06);
}
.facet-item.active {
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

.data {
  font-family: ui-monospace, SFMono-Regular, monospace;
  font-size: 12px;
  word-break: break-all;
}

.link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.link:hover { text-decoration: underline; }

@media (max-width: 900px) {
  .layout { grid-template-columns: 1fr; }
}
</style>
