<script setup lang="ts">
// FindingDetail —— 漏洞详情 + 状态机转移 + 评论 timeline（PR-S26）。
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { findingClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { Finding, FindingEvent } from '@/gen/proto/redmatrix/finding/v1/finding_pb';

const STATUS_LABELS: Record<string, string> = {
  open: '待处理',
  triaged: '已分派',
  confirmed: '已确认',
  fixed: '已修复',
  false_positive: '误报',
};

// 转移表（与 domain.allowedTransitions 一致）
const TRANSITIONS: Record<string, string[]> = {
  open: ['triaged', 'false_positive', 'fixed'],
  triaged: ['confirmed', 'false_positive', 'open'],
  confirmed: ['fixed', 'false_positive'],
  false_positive: ['open'],
  fixed: ['open'],
};

const route = useRoute();
const router = useRouter();
const toast = useToast();

const id = computed(() => String(route.params.id || ''));
const finding = ref<Finding | null>(null);
const events = ref<FindingEvent[]>([]);
const loading = ref(false);
const submitting = ref(false);
const nowTick = ref(Date.now());

const commentBody = ref('');
const showTransition = ref<{ to: string } | null>(null);
const transitionComment = ref('');

async function refresh() {
  if (!id.value) return;
  loading.value = true;
  try {
    const [f, e] = await Promise.all([
      findingClient.getFinding({ id: id.value }),
      findingClient.listEvents({ findingId: id.value }),
    ]);
    finding.value = f.finding || null;
    events.value = e.events;
  } catch (err) {
    toast.error(errorMessage(err));
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  await refresh();
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

const availableTransitions = computed<string[]>(() => {
  if (!finding.value) return [];
  return TRANSITIONS[finding.value.status] || [];
});

async function doTransition() {
  if (!showTransition.value || !finding.value || submitting.value) return;
  submitting.value = true;
  try {
    await findingClient.transition({
      id: finding.value.id,
      toStatus: showTransition.value.to,
      comment: transitionComment.value,
    });
    toast.success(`已转 ${STATUS_LABELS[showTransition.value.to] || showTransition.value.to}`);
    showTransition.value = null;
    transitionComment.value = '';
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function submitComment() {
  if (!finding.value || !commentBody.value.trim() || submitting.value) return;
  submitting.value = true;
  try {
    await findingClient.comment({ findingId: finding.value.id, body: commentBody.value });
    commentBody.value = '';
    toast.success('评论已添加');
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

function severityBadge(s: string) {
  switch (s) {
    case 'critical': return 'red';
    case 'high':     return 'amber';
    case 'medium':   return 'amber';
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
function eventLabel(e: FindingEvent): string {
  switch (e.kind) {
    case 'created':
      return '系统：创建';
    case 'occurrence':
      return '系统：再次扫到';
    case 'status_change':
      return `状态：${statusLabel(e.fromStatus)} → ${statusLabel(e.toStatus)}`;
    case 'comment':
      return '评论';
    case 'assignee_change':
      return '指派变更';
  }
  return e.kind;
}
</script>

<template>
  <div class="detail">
    <div class="head">
      <button class="back" @click="router.push('/findings')">← 返回漏洞列表</button>
    </div>

    <template v-if="finding">
      <div class="card">
        <div class="row meta-row">
          <span class="badge" :class="severityBadge(finding.severity)">{{ finding.severity }}</span>
          <span class="badge" :class="statusBadge(finding.status)">{{ statusLabel(finding.status) }}</span>
          <span class="muted">·</span>
          <span class="muted">命中 {{ finding.occurrenceCount }} 次</span>
        </div>
        <h1 class="title">{{ finding.title }}</h1>

        <div class="kv">
          <div class="kv-row"><span class="kv-k">Template</span><code>{{ finding.templateId }}</code></div>
          <div class="kv-row"><span class="kv-k">Host</span><code>{{ finding.host }}</code></div>
          <div class="kv-row" v-if="finding.firstSeenAt">
            <span class="kv-k">首次发现</span>
            <span :title="formatAbsoluteTime(finding.firstSeenAt)">
              {{ formatAbsoluteTime(finding.firstSeenAt) }}（{{ formatRelativeTime(finding.firstSeenAt, nowTick) }}）
            </span>
          </div>
          <div class="kv-row" v-if="finding.lastSeenAt">
            <span class="kv-k">最近一次</span>
            <span :title="formatAbsoluteTime(finding.lastSeenAt)">
              {{ formatAbsoluteTime(finding.lastSeenAt) }}（{{ formatRelativeTime(finding.lastSeenAt, nowTick) }}）
            </span>
          </div>
        </div>

        <div v-if="finding.description" class="section">
          <h3>描述</h3>
          <p class="muted">{{ finding.description }}</p>
        </div>
        <div v-if="finding.reference" class="section">
          <h3>参考</h3>
          <pre class="ref">{{ finding.reference }}</pre>
        </div>

        <div class="section">
          <h3>转移状态</h3>
          <div class="row" style="gap: 6px; flex-wrap: wrap">
            <button v-for="t in availableTransitions" :key="t" class="primary" @click="showTransition = { to: t }">
              → {{ statusLabel(t) }}
            </button>
            <span v-if="availableTransitions.length === 0" class="muted">无可用转移</span>
          </div>
        </div>
      </div>

      <div class="card">
        <h3>评论 / 操作流水</h3>
        <div class="comment-form">
          <textarea v-model="commentBody" placeholder="添加评论…" :disabled="submitting" rows="3" style="width: 100%" />
          <div class="row" style="margin-top: 6px; justify-content: flex-end">
            <button class="primary" :disabled="submitting || !commentBody.trim()" @click="submitComment">
              {{ submitting ? '提交中…' : '提交评论' }}
            </button>
          </div>
        </div>
        <div class="timeline">
          <div v-for="e in events" :key="e.id" class="event">
            <div class="row" style="gap: 8px; align-items: center">
              <span class="event-kind">{{ eventLabel(e) }}</span>
              <span class="muted" style="font-size: 12px" :title="formatAbsoluteTime(e.createdAt)">
                {{ formatRelativeTime(e.createdAt, nowTick) }}
              </span>
            </div>
            <p v-if="e.body" class="event-body">{{ e.body }}</p>
          </div>
          <p v-if="events.length === 0" class="muted" style="text-align: center">暂无流水。</p>
        </div>
      </div>
    </template>

    <p v-else-if="loading" class="muted">加载中…</p>
    <p v-else class="muted">未找到漏洞（id={{ id }}）。</p>

    <!-- 转移确认 modal -->
    <div v-if="showTransition" class="modal-mask">
      <div class="card modal">
        <h3>转移到：{{ statusLabel(showTransition.to) }}</h3>
        <textarea v-model="transitionComment" placeholder="可选：注明原因 / 触发评论" rows="4" style="width: 100%" />
        <div class="row" style="margin-top: 12px; justify-content: flex-end; gap: 8px">
          <button :disabled="submitting" @click="showTransition = null">取消</button>
          <button class="primary" :disabled="submitting" @click="doTransition">
            {{ submitting ? '提交中…' : '确认转移' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.detail { display: flex; flex-direction: column; gap: 16px; }
.head { display: flex; justify-content: space-between; }
.back {
  background: transparent; border: none; color: var(--accent, #2563eb);
  font-size: 13px; cursor: pointer; padding: 4px 0;
}
.back:hover { text-decoration: underline; }
.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.title { font-size: 20px; font-weight: 600; margin: 4px 0 12px; }
.meta-row { gap: 8px; font-size: 13px; align-items: center; }
.muted { color: var(--muted, #6b7280); }
.kv { display: flex; flex-direction: column; gap: 4px; font-size: 13px; }
.kv-row { display: flex; gap: 12px; }
.kv-k { color: var(--muted, #6b7280); min-width: 80px; }
.section { margin-top: 16px; }
.section h3 { margin: 0 0 8px; font-size: 14px; }
.ref { background: var(--surface-alt, #f8fafc); padding: 8px; border-radius: 4px; font-size: 12px; white-space: pre-wrap; }
.badge.blue { background: rgba(59, 130, 246, 0.16); color: #1d4ed8; }
.badge.green { background: rgba(22, 163, 74, 0.16); color: #166534; }
.badge.amber { background: rgba(245, 158, 11, 0.16); color: #92400e; }
.badge.red { background: rgba(239, 68, 68, 0.16); color: #991b1b; }
.timeline { margin-top: 16px; display: flex; flex-direction: column; gap: 12px; }
.event {
  border-left: 2px solid var(--border, #e2e8f0);
  padding: 6px 0 6px 12px;
}
.event-kind { font-size: 13px; font-weight: 500; }
.event-body { margin: 4px 0 0; font-size: 13px; white-space: pre-wrap; }
.comment-form { margin-bottom: 12px; }
.modal-mask {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.36);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.modal {
  width: min(520px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}
</style>
