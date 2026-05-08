<script setup lang="ts">
// Dashboard —— 登录后的概览页（PR-W5）。
//
// MVP 用现有 list 接口聚合 4 张 KPI 卡：
//   - 项目数（active）
//   - 节点总数
//   - 在线节点数（status=online；handler 已走 DeriveStatus 包过期 demote）
//   - 活跃注册令牌（未撤、未用、未过期）
//
// 30s 自动刷新；Promise.all 并行抓三个 list，单个失败仅 toast 不阻塞其它卡。
//
// 后续后端补 SystemService.GetStats 时把这里改成 single-call。
import { ref, onMounted, onUnmounted, computed } from 'vue';
import { useRouter } from 'vue-router';

import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime } from '@/util/relativeTime';
import type {
  Node,
  RegistrationToken,
} from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const router = useRouter();
const toast = useToast();

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';
const REFRESH_INTERVAL_MS = 30_000;

const loading = ref(false);
const projectsCount = ref(0);
const projectsArchived = ref(0);
const nodes = ref<Node[]>([]);
const tokens = ref<RegistrationToken[]>([]);
const lastRefreshedAt = ref<number | null>(null);

const nowTick = ref(Date.now());
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

const onlineNodes = computed(() => nodes.value.filter((n) => n.status === 'online').length);
const offlineNodes = computed(() => nodes.value.filter((n) => n.status === 'offline').length);
const pendingNodes = computed(() => nodes.value.filter((n) => n.status === 'pending').length);
const disabledNodes = computed(() => nodes.value.filter((n) => n.status === 'disabled').length);

const activeTokens = computed(() => {
  const now = Date.now();
  return tokens.value.filter((t) => {
    if (t.usedAt) return false;
    if (t.revokedAt) return false;
    if (t.expiresAt && t.expiresAt.toDate().getTime() < now) return false;
    return true;
  }).length;
});

async function fetchProjects() {
  try {
    const r = await tenancyClient.listProjects({
      tenantId: DEFAULT_TENANT_ID,
      page: 1,
      pageSize: 100,
    });
    projectsCount.value = r.projects.filter((p) => p.status === 'active').length;
    projectsArchived.value = r.projects.filter((p) => p.status === 'archived').length;
  } catch (e) {
    toast.error('项目数加载失败：' + errorMessage(e));
  }
}

async function fetchNodes() {
  try {
    const r = await tenancyClient.listNodes({
      tenantId: DEFAULT_TENANT_ID,
      page: 1,
      pageSize: 100,
    });
    nodes.value = r.nodes;
  } catch (e) {
    toast.error('节点数加载失败：' + errorMessage(e));
  }
}

async function fetchTokens() {
  // PA / 普通 user 后端会拒（SA only），此卡仅对 SA / Auditor 显示
  if (!authStore.isSuperAdmin() && !authStore.isAuditor()) return;
  try {
    const r = await tenancyClient.listRegistrationTokens({ tenantId: DEFAULT_TENANT_ID });
    tokens.value = r.tokens;
  } catch (e) {
    // SA 才能列；忽略 403 不打扰用户
  }
}

async function refresh() {
  loading.value = true;
  try {
    await Promise.all([fetchProjects(), fetchNodes(), fetchTokens()]);
    lastRefreshedAt.value = Date.now();
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
        <div class="stat-num">{{ projectsCount }}</div>
        <div class="stat-foot">
          <span v-if="projectsArchived > 0" class="muted">+{{ projectsArchived }} 已归档</span>
          <span v-else class="muted">活跃项目数</span>
        </div>
      </button>

      <!-- Total nodes -->
      <button class="card stat" @click="go('/nodes')">
        <div class="stat-label">节点</div>
        <div class="stat-num">{{ nodes.length }}</div>
        <div class="stat-foot">
          <span class="badge-mini badge-amber" v-if="pendingNodes > 0">{{ pendingNodes }} pending</span>
          <span class="badge-mini badge-red" v-if="disabledNodes > 0">{{ disabledNodes }} disabled</span>
          <span v-if="!pendingNodes && !disabledNodes" class="muted">总注册数</span>
        </div>
      </button>

      <!-- Online -->
      <button class="card stat stat-emphasis" @click="go('/nodes')">
        <div class="stat-label">在线节点</div>
        <div class="stat-num">
          <span class="dot dot-green stat-dot" v-if="onlineNodes > 0" />
          {{ onlineNodes }}
        </div>
        <div class="stat-foot">
          <span v-if="offlineNodes > 0" class="muted">{{ offlineNodes }} 已离线</span>
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
      <div v-if="nodes.length === 0" class="muted">尚未注册节点。在节点页用 RegistrationToken 接入 Agent 后会显示。</div>
      <div v-else class="bar">
        <span
          v-if="onlineNodes > 0"
          class="bar-seg seg-green"
          :style="{ flex: onlineNodes }"
          :title="`${onlineNodes} online`"
        />
        <span
          v-if="pendingNodes > 0"
          class="bar-seg seg-amber"
          :style="{ flex: pendingNodes }"
          :title="`${pendingNodes} pending`"
        />
        <span
          v-if="offlineNodes > 0"
          class="bar-seg seg-gray"
          :style="{ flex: offlineNodes }"
          :title="`${offlineNodes} offline`"
        />
        <span
          v-if="disabledNodes > 0"
          class="bar-seg seg-red"
          :style="{ flex: disabledNodes }"
          :title="`${disabledNodes} disabled`"
        />
      </div>
      <div v-if="nodes.length > 0" class="legend">
        <span><span class="dot dot-green" /> online {{ onlineNodes }}</span>
        <span><span class="dot dot-amber" /> pending {{ pendingNodes }}</span>
        <span><span class="dot dot-gray" /> offline {{ offlineNodes }}</span>
        <span><span class="dot dot-red" /> disabled {{ disabledNodes }}</span>
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
