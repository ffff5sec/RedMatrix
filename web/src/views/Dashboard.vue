<script setup lang="ts">
// Dashboard —— 登录后的概览页（PR-W5；PR-W7 改用 GetStats single-call）。
//
// 之前 3 个 list 调用客户端聚合 → 一个 GetStats RPC。PA 角色后端拒
// （SA / Auditor only），UI 静默退化为全 0（不打扰用户）。
import { ref, onMounted, onUnmounted, computed } from 'vue';
import { useRouter } from 'vue-router';

import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime } from '@/util/relativeTime';
import type { GetStatsResponse } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const router = useRouter();
const toast = useToast();

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const REFRESH_INTERVAL_MS = 30_000;

const loading = ref(false);
const stats = ref<GetStatsResponse | null>(null);
const lastRefreshedAt = ref<number | null>(null);

const nowTick = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

// === 派生 KPI（stats 未加载时全 0）===
const projectsActive    = computed(() => stats.value?.projectsActive ?? 0);
const projectsArchived  = computed(() => stats.value?.projectsArchived ?? 0);
const nodesTotal        = computed(() => stats.value?.nodesTotal ?? 0);
const nodesOnline       = computed(() => stats.value?.nodesOnline ?? 0);
const nodesPending      = computed(() => stats.value?.nodesPending ?? 0);
const nodesOffline      = computed(() => stats.value?.nodesOffline ?? 0);
const nodesDisabled     = computed(() => stats.value?.nodesDisabled ?? 0);
const activeTokens      = computed(() => stats.value?.registrationTokensActive ?? 0);

async function refresh() {
  loading.value = true;
  try {
    const r = await tenancyClient.getStats({ tenantId: DEFAULT_TENANT_ID });
    stats.value = r;
    lastRefreshedAt.value = Date.now();
  } catch (e) {
    // PA 角色 403 → 静默；其它失败弹 toast
    if (authStore.isSuperAdmin() || authStore.isAuditor()) {
      toast.error('概览加载失败：' + errorMessage(e));
    }
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

function go(path: string) {
  router.push(path);
}

const lastRefreshLabel = computed(() => {
  if (lastRefreshedAt.value == null) return '加载中…';
  return formatRelativeTime(lastRefreshedAt.value, nowTick.value, '刚刚');
});
</script>

<template>
  <div class="dashboard">
    <div class="page-head">
      <div>
        <h1 class="title">概览</h1>
        <p class="subtitle">RedMatrix 实例当前态势 · 30 秒自动刷新</p>
      </div>
      <div class="meta">
        <span class="dot" :class="loading ? 'dot-amber' : 'dot-green'" />
        <span class="muted">{{ loading ? '刷新中' : `更新于 ${lastRefreshLabel}` }}</span>
      </div>
    </div>

    <div class="grid">
      <!-- Projects -->
      <button class="card stat" @click="go('/projects')">
        <div class="stat-label">项目</div>
        <div class="stat-num">{{ projectsActive }}</div>
        <div class="stat-foot">
          <span v-if="projectsArchived > 0" class="muted">+{{ projectsArchived }} 已归档</span>
          <span v-else class="muted">活跃项目数</span>
        </div>
      </button>

      <!-- Total nodes -->
      <button class="card stat" @click="go('/nodes')">
        <div class="stat-label">节点</div>
        <div class="stat-num">{{ nodesTotal }}</div>
        <div class="stat-foot">
          <span class="badge-mini badge-amber" v-if="nodesPending > 0">{{ nodesPending }} pending</span>
          <span class="badge-mini badge-red" v-if="nodesDisabled > 0">{{ nodesDisabled }} disabled</span>
          <span v-if="!nodesPending && !nodesDisabled" class="muted">总注册数</span>
        </div>
      </button>

      <!-- Online -->
      <button class="card stat stat-emphasis" @click="go('/nodes')">
        <div class="stat-label">在线节点</div>
        <div class="stat-num">
          <span class="dot dot-green stat-dot" v-if="nodesOnline > 0" />
          {{ nodesOnline }}
        </div>
        <div class="stat-foot">
          <span v-if="nodesOffline > 0" class="muted">{{ nodesOffline }} 已离线</span>
          <span v-else class="muted">实时心跳</span>
        </div>
      </button>

      <!-- Active tokens -->
      <button
        class="card stat"
        :disabled="!authStore.isSuperAdmin() && !authStore.isAuditor()"
        @click="go('/nodes')"
      >
        <div class="stat-label">活跃令牌</div>
        <div class="stat-num">{{ activeTokens }}</div>
        <div class="stat-foot">
          <span class="muted">未撤未用未过期</span>
        </div>
      </button>
    </div>

    <!-- 节点状态明细 -->
    <div class="card">
      <h2>节点状态分布</h2>
      <div v-if="nodesTotal === 0" class="muted">尚未注册节点。在节点页用 RegistrationToken 接入 Agent 后会显示。</div>
      <div v-else class="bar">
        <span
          v-if="nodesOnline > 0"
          class="bar-seg seg-green"
          :style="{ flex: nodesOnline }"
          :title="`${nodesOnline} online`"
        />
        <span
          v-if="nodesPending > 0"
          class="bar-seg seg-amber"
          :style="{ flex: nodesPending }"
          :title="`${nodesPending} pending`"
        />
        <span
          v-if="nodesOffline > 0"
          class="bar-seg seg-gray"
          :style="{ flex: nodesOffline }"
          :title="`${nodesOffline} offline`"
        />
        <span
          v-if="nodesDisabled > 0"
          class="bar-seg seg-red"
          :style="{ flex: nodesDisabled }"
          :title="`${nodesDisabled} disabled`"
        />
      </div>
      <div v-if="nodesTotal > 0" class="legend">
        <span><span class="dot dot-green" /> online {{ nodesOnline }}</span>
        <span><span class="dot dot-amber" /> pending {{ nodesPending }}</span>
        <span><span class="dot dot-gray" /> offline {{ nodesOffline }}</span>
        <span><span class="dot dot-red" /> disabled {{ nodesDisabled }}</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dashboard {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.page-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.title {
  font-size: 20px;
  font-weight: 600;
  margin: 0;
  color: var(--text, #1f2937);
}

.subtitle {
  font-size: 13px;
  margin: 4px 0 0;
  color: var(--muted, #6b7280);
}

.meta {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
}

.muted {
  color: var(--muted, #6b7280);
}

.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
}

.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}

.stat {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  text-align: left;
  cursor: pointer;
  transition: transform 100ms ease, border-color 100ms ease;
}

.stat:hover:not(:disabled) {
  transform: translateY(-1px);
  border-color: var(--accent, #2563eb);
}

.stat:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.stat-emphasis {
  background: linear-gradient(180deg, rgba(34, 197, 94, 0.06), transparent 60%);
}

.stat-label {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--muted, #6b7280);
}

.stat-num {
  font-size: 32px;
  font-weight: 600;
  margin: 8px 0;
  display: flex;
  align-items: center;
  gap: 8px;
  line-height: 1;
}

.stat-dot {
  width: 10px !important;
  height: 10px !important;
}

.stat-foot {
  font-size: 12px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

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

.badge-mini {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  font-size: 11px;
}
.badge-amber { background: rgba(245, 158, 11, 0.16); color: #b45309; }
.badge-red   { background: rgba(239, 68, 68, 0.16); color: #b91c1c; }

.bar {
  display: flex;
  height: 14px;
  border-radius: 7px;
  overflow: hidden;
  background: rgba(0, 0, 0, 0.04);
  margin-top: 12px;
}
.bar-seg { display: block; }
.seg-green { background: #22c55e; }
.seg-amber { background: #f59e0b; }
.seg-gray  { background: #9ca3af; }
.seg-red   { background: #ef4444; }

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-top: 10px;
  font-size: 12px;
  color: var(--muted, #6b7280);
}
.legend > span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
</style>
