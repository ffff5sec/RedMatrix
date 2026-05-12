<script setup lang="ts">
// SuiteRunDetail —— 套件运行详情（PR-S23）。
//
// 范围：显示 run.status + targets + 关联 N 子 task 列表（带跳转 + 自动刷新）。
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { scanClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { ScanSuite, ScanSuiteRun, ScanTask } from '@/gen/proto/redmatrix/scan/v1/scan_pb';

const route = useRoute();
const router = useRouter();
const toast = useToast();

const runID = computed(() => String(route.params.id || ''));
const run = ref<ScanSuiteRun | null>(null);
const suite = ref<ScanSuite | null>(null);
const tasks = ref<ScanTask[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());

let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

async function refresh() {
  if (!runID.value) return;
  loading.value = true;
  try {
    const r = await scanClient.getScanSuiteRun({ id: runID.value });
    run.value = r.run || null;
    suite.value = r.suite || null;
    tasks.value = r.tasks;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  refresh();
  refreshTimer = setInterval(refresh, 15_000);
  tickTimer = setInterval(() => (nowTick.value = Date.now()), 1000);
});
onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (tickTimer) clearInterval(tickTimer);
});

function statusBadge(s: string) {
  switch (s) {
    case 'pending':        return 'amber';
    case 'running':        return 'blue';
    case 'completed':      return 'green';
    case 'partial_failed': return 'amber';
    case 'failed':         return 'red';
    case 'canceled':       return '';
    default:               return '';
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

// PR-S27 chaining：根据 run.currentStep 渲染 step 状态
function stepClass(i: number): string {
  if (!run.value) return '';
  const cur = run.value.currentStep;
  const status = run.value.status;
  if (status === 'failed' && i === cur) return 'failed';
  if (status === 'completed' && i <= cur) return 'done';
  if (i < cur) return 'done';
  if (i === cur && status === 'running') return 'active';
  if (i === cur && status === 'pending') return 'pending';
  return 'todo';
}

function stepIcon(i: number): string {
  if (!run.value) return '';
  const cur = run.value.currentStep;
  const status = run.value.status;
  if (status === 'failed' && i === cur) return '✗';
  if (status === 'completed' && i <= cur) return '✓';
  if (i < cur) return '✓';
  if (i === cur && status === 'running') return '◐';
  return '';
}
</script>

<template>
  <div class="detail">
    <div class="head">
      <button class="back" @click="router.push('/scan-suites')">← 返回套件列表</button>
    </div>

    <template v-if="run">
      <div class="card">
        <h1 class="title">套件运行</h1>
        <div class="row meta-row">
          <span class="badge" :class="statusBadge(run.status)">{{ run.status }}</span>
          <span class="muted">·</span>
          <span class="muted">套件 <code>{{ suite ? suite.name : '<已删除>' }}</code></span>
          <span class="muted">·</span>
          <span class="muted">{{ tasks.length }} 个子 task</span>
        </div>

        <div class="kv">
          <div class="kv-row"><span class="kv-k">Run ID</span><code>{{ run.id }}</code></div>
          <div class="kv-row" v-if="run.createdAt">
            <span class="kv-k">创建</span>
            <span :title="formatAbsoluteTime(run.createdAt)">
              {{ formatAbsoluteTime(run.createdAt) }}（{{ formatRelativeTime(run.createdAt, nowTick) }}）
            </span>
          </div>
          <div class="kv-row" v-if="run.finishedAt">
            <span class="kv-k">结束</span>
            <span :title="formatAbsoluteTime(run.finishedAt)">
              {{ formatAbsoluteTime(run.finishedAt) }}（{{ formatRelativeTime(run.finishedAt, nowTick) }}）
            </span>
          </div>
        </div>
      </div>

      <!-- PR-S27 chaining pipeline 视图 -->
      <div class="card" v-if="suite && suite.kinds && suite.kinds.length > 0">
        <h2>执行步骤 <span class="muted">（chaining）</span></h2>
        <p class="muted">
          套件按数组顺序串行执行；前一步的输出（subdomain → host，fingerprint → live URL）
          自动喂给下一步。
        </p>
        <div class="pipeline">
          <template v-for="(k, i) in suite.kinds" :key="i">
            <div class="step" :class="stepClass(i)">
              <span class="step-idx">{{ i + 1 }}</span>
              <span class="step-kind">{{ kindLabel(k) }}</span>
              <span class="step-icon">{{ stepIcon(i) }}</span>
            </div>
            <span v-if="i < suite.kinds.length - 1" class="step-arrow">→</span>
          </template>
        </div>
      </div>

      <div class="card" v-if="run.targets && run.targets.length > 0">
        <h2>初始目标列表 <span class="muted">（{{ run.targets.length }}）</span></h2>
        <ul class="targets-list">
          <li v-for="(t, i) in run.targets" :key="i"><code>{{ t }}</code></li>
        </ul>
      </div>

      <div class="card">
        <h2>子任务 <span class="muted">（{{ tasks.length }}）</span></h2>
        <p class="muted">
          套件展开生成的每个 kind 一个 task。点开看派发 / 结果。
        </p>
        <table v-if="tasks.length > 0">
          <thead>
            <tr>
              <th>任务名</th>
              <th>类型</th>
              <th>状态</th>
              <th>创建</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tasks" :key="t.id">
              <td>
                <router-link :to="`/scans/${t.id}`" class="link">{{ t.name }}</router-link>
              </td>
              <td><span class="chip">{{ kindLabel(t.kind) }}</span></td>
              <td><span class="badge" :class="statusBadge(t.status)">{{ t.status }}</span></td>
              <td class="muted" :title="formatAbsoluteTime(t.createdAt)">
                {{ formatRelativeTime(t.createdAt, nowTick) }}
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted" style="text-align: center; padding: 24px">
          暂无关联 task。可能 run 已删除 / 还在写库。
        </p>
      </div>
    </template>

    <p v-else-if="loading" class="muted">加载中…</p>
    <p v-else class="muted">未找到 run（id={{ runID }}）。</p>
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
.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.kv { margin-top: 8px; display: flex; flex-direction: column; gap: 4px; font-size: 13px; }
.kv-row { display: flex; gap: 12px; }
.kv-k { color: var(--muted, #6b7280); min-width: 80px; }
.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
}
.badge.blue {
  background: rgba(59, 130, 246, 0.16);
  color: #1d4ed8;
}
.targets-list {
  margin: 8px 0 0;
  padding-left: 18px;
  max-height: 240px;
  overflow: auto;
  font-size: 13px;
}
.targets-list li { margin: 2px 0; }
.targets-list code { font-family: ui-monospace, SFMono-Regular, monospace; }
.link {
  color: var(--accent, #2563eb);
  text-decoration: none;
}
.link:hover { text-decoration: underline; }
.pipeline {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 12px;
}
.step {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 8px 14px;
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  background: var(--surface, #fff);
  font-size: 13px;
}
.step-idx {
  background: rgba(0, 0, 0, 0.06);
  width: 20px;
  height: 20px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 50%;
  font-size: 11px;
  font-weight: 600;
}
.step-kind { font-weight: 500; }
.step-icon { font-weight: 600; }
.step-arrow {
  color: var(--muted, #6b7280);
  font-size: 16px;
  font-weight: 600;
}
.step.done {
  background: rgba(22, 163, 74, 0.08);
  border-color: rgba(22, 163, 74, 0.4);
  color: #166534;
}
.step.done .step-idx { background: rgba(22, 163, 74, 0.2); color: #166534; }
.step.active {
  background: rgba(59, 130, 246, 0.10);
  border-color: rgba(59, 130, 246, 0.5);
  color: #1d4ed8;
  animation: pulse 1.5s ease-in-out infinite;
}
.step.active .step-idx { background: rgba(59, 130, 246, 0.25); color: #1d4ed8; }
.step.failed {
  background: rgba(239, 68, 68, 0.08);
  border-color: rgba(239, 68, 68, 0.4);
  color: #991b1b;
}
.step.failed .step-idx { background: rgba(239, 68, 68, 0.2); color: #991b1b; }
.step.pending { color: var(--muted, #6b7280); }
.step.todo { color: var(--muted, #6b7280); opacity: 0.7; }
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
}
</style>
