<script setup lang="ts">
// AssetDetail —— 资产详情（PR-S8）。
//
// 显示资产元数据 + 该资产关联的扫描结果（复用 ScanService.SearchResults
// 接口按 keyword=value 反查；未来可扩展为按资产 ID 直查）。
import { ref, onMounted, onUnmounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { assetClient, findingClient, scanClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { Asset } from '@/gen/proto/redmatrix/asset/v1/asset_pb';
import type { Finding } from '@/gen/proto/redmatrix/finding/v1/finding_pb';
import type { ScanResult } from '@/gen/proto/redmatrix/scan/v1/scan_pb';

const route = useRoute();
const router = useRouter();
const toast = useToast();

const asset = ref<Asset | null>(null);
const results = ref<ScanResult[]>([]);
const resultsTotal = ref(0);
const findings = ref<Finding[]>([]);
const findingsTotal = ref(0);
const loading = ref(false);

const nowTick = ref(Date.now());
let tickTimer: ReturnType<typeof setInterval> | null = null;

async function refresh() {
  const id = String(route.params.id || '');
  if (!id) return;
  loading.value = true;
  try {
    const r = await assetClient.getAsset({ id });
    asset.value = r.asset || null;
    if (asset.value) {
      // 用 SearchResults 拉相关结果（按项目过滤 + 关键字 = value）。
      const sr = await scanClient.searchResults({
        keyword: asset.value.value,
        projectId: asset.value.projectId,
        page: 1,
        pageSize: 100,
      });
      results.value = sr.results;
      resultsTotal.value = sr.total;
      // PR-S70：拉该资产的漏洞工单
      try {
        const fr = await findingClient.listFindings({
          assetId: asset.value.id,
          page: 1,
          pageSize: 100,
        });
        findings.value = fr.findings;
        findingsTotal.value = fr.total;
      } catch {
        // 静默；finding 模块未启用时不阻断详情页
        findings.value = [];
        findingsTotal.value = 0;
      }
    }
  } catch (e) {
    toast.error(errorMessage(e));
    router.push('/assets');
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  refresh();
  tickTimer = setInterval(() => { nowTick.value = Date.now(); }, 1_000);
});
onUnmounted(() => {
  if (tickTimer) clearInterval(tickTimer);
});

function severityBadge(s: string) {
  return `sev-${s}`;
}
function statusLabel(s: string) {
  switch (s) {
    case 'open': return '待处理';
    case 'triaged': return '已分派';
    case 'confirmed': return '已确认';
    case 'fixed': return '已修复';
    case 'false_positive': return '误报';
    default: return s;
  }
}

function kindLabel(k: string) {
  switch (k) {
    case 'host': return '主机';
    case 'subdomain': return '子域名';
    case 'url': return 'URL';
    case 'port_scan': return '端口扫描';
    case 'web_crawl': return '网页爬取';
    case 'fingerprint': return '指纹识别';
    default: return k;
  }
}

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
</script>

<template>
  <div class="page">
    <div class="row" style="gap: 8px">
      <button @click="router.push('/assets')">← 返回</button>
      <h2 style="margin: 0">资产详情</h2>
    </div>

    <div v-if="loading && !asset" class="muted">加载中…</div>

    <div v-if="asset" class="card">
      <div class="form">
        <div class="form-row">
          <span class="label">类型</span>
          <span class="chip">{{ kindLabel(asset.kind) }}</span>
        </div>
        <div class="form-row">
          <span class="label">值</span>
          <code class="value">{{ asset.value }}</code>
        </div>
        <div class="form-row">
          <span class="label">项目</span>
          <span class="muted">{{ asset.projectId }}</span>
        </div>
        <div class="form-row">
          <span class="label">命中数</span>
          <span>{{ asset.resultCount }}</span>
        </div>
        <div class="form-row">
          <span class="label">首次发现</span>
          <span class="muted">
            {{ formatAbsoluteTime(asset.firstSeen) }}（{{ formatRelativeTime(asset.firstSeen, nowTick) }}）
          </span>
        </div>
        <div class="form-row">
          <span class="label">最近活跃</span>
          <span class="muted">
            {{ formatAbsoluteTime(asset.lastSeen) }}（{{ formatRelativeTime(asset.lastSeen, nowTick) }}）
          </span>
        </div>
      </div>
    </div>

    <div v-if="asset" class="card">
      <h3 style="margin-top: 0">关联漏洞（{{ findingsTotal }}）</h3>
      <table v-if="findings.length > 0">
        <thead>
          <tr>
            <th style="width: 90px">严重度</th>
            <th style="width: 90px">状态</th>
            <th>标题</th>
            <th style="width: 80px">次数</th>
            <th style="width: 140px">最近</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in findings" :key="f.id">
            <td><span class="badge" :class="severityBadge(f.severity)">{{ f.severity }}</span></td>
            <td>{{ statusLabel(f.status) }}</td>
            <td>
              <router-link :to="`/findings/${f.id}`" class="link">{{ f.title }}</router-link>
              <span class="muted" style="margin-left: 8px; font-size: 12px">{{ f.templateId }}</span>
            </td>
            <td>{{ f.occurrenceCount }}</td>
            <td class="muted" :title="formatAbsoluteTime(f.lastSeenAt)">
              {{ formatRelativeTime(f.lastSeenAt, nowTick) }}
            </td>
          </tr>
        </tbody>
      </table>
      <div v-else class="muted" style="text-align: center; padding: 16px">
        该资产暂无关联漏洞。
      </div>
    </div>

    <div v-if="asset" class="card">
      <h3 style="margin-top: 0">关联扫描结果（{{ resultsTotal }}）</h3>
      <table>
        <thead>
          <tr>
            <th style="width: 110px">类型</th>
            <th>数据</th>
            <th style="width: 140px">时间</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in results" :key="r.id">
            <td><span class="chip">{{ kindLabel(r.kind) }}</span></td>
            <td><code class="data">{{ formatData(r.data) }}</code></td>
            <td class="muted" :title="formatAbsoluteTime(r.createdAt)">
              {{ formatRelativeTime(r.createdAt, nowTick) }}
            </td>
          </tr>
          <tr v-if="results.length === 0 && !loading">
            <td colspan="3" class="muted" style="text-align: center; padding: 24px">
              暂无关联结果。
            </td>
          </tr>
        </tbody>
      </table>
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
.form { display: flex; flex-direction: column; gap: 10px; }
.form-row { display: flex; align-items: center; gap: 12px; }
.label { width: 90px; color: var(--muted, #6b7280); font-size: 13px; }

.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}
.value { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px; word-break: break-all; }
.data { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; word-break: break-all; }
.link { color: var(--accent, #2563eb); text-decoration: none; }
.link:hover { text-decoration: underline; }
.badge {
  display: inline-block; border-radius: 4px; padding: 1px 8px;
  font-size: 12px; font-weight: 500;
}
.sev-critical { background: rgba(207, 19, 34, 0.12); color: #cf1322; }
.sev-high     { background: rgba(250, 84, 28, 0.12); color: #fa541c; }
.sev-medium   { background: rgba(250, 173, 20, 0.18); color: #ad6800; }
.sev-low      { background: rgba(19, 194, 194, 0.12); color: #08979c; }
.sev-info     { background: rgba(140, 140, 140, 0.18); color: #595959; }
</style>
