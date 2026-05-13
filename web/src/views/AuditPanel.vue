<script setup lang="ts">
// AuditPanel —— 审计日志（PR-S33；SA / Auditor）。
//
// 表格 + filter + JSON 展开 + 链完整性校验按钮。
import { ref, computed, onMounted } from 'vue';
import { Timestamp } from '@bufbuild/protobuf';

import { auditClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { AuditLog } from '@/gen/proto/redmatrix/audit/v1/audit_pb';

const toast = useToast();

const logs = ref<AuditLog[]>([]);
const total = ref(0);
const loading = ref(false);
const nowTick = ref(Date.now());
const filterAction = ref('');
const filterResourceKind = ref('');
const filterActorUserID = ref('');
const filterTimeFrom = ref(''); // datetime-local 字符串
const filterTimeTo = ref('');
const expanded = ref<Record<string, boolean>>({});

const ACTION_OPTIONS = [
  { value: '', label: '所有 action' },
  { value: 'login', label: 'login' },
  { value: 'logout', label: 'logout' },
  { value: 'password_changed', label: 'password_changed' },
  { value: 'api_key_created', label: 'api_key_created' },
  { value: 'api_key_revoked', label: 'api_key_revoked' },
  { value: 'task_create', label: 'task_create' },
  { value: 'task_cancel', label: 'task_cancel' },
  { value: 'task_delete', label: 'task_delete' },
  { value: 'suite_run', label: 'suite_run' },
  { value: 'finding_transition', label: 'finding_transition' },
  { value: 'finding_comment', label: 'finding_comment' },
];

async function refresh() {
  loading.value = true;
  try {
    const r = await auditClient.listLogs({
      action: filterAction.value || undefined,
      resourceKind: filterResourceKind.value || undefined,
      actorUserId: filterActorUserID.value || undefined,
      timeFrom: filterTimeFrom.value
        ? Timestamp.fromDate(new Date(filterTimeFrom.value))
        : undefined,
      timeTo: filterTimeTo.value
        ? Timestamp.fromDate(new Date(filterTimeTo.value))
        : undefined,
      page: 1,
      pageSize: 100,
    });
    logs.value = r.logs;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  refresh();
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

const verifyResult = ref<{ ok: boolean; total: number; breakAtIndex: number; breakAtId: string } | null>(null);
const verifying = ref(false);

async function runVerify() {
  if (verifying.value) return;
  verifying.value = true;
  try {
    const r = await auditClient.verifyChain({ limit: 500 });
    verifyResult.value = {
      ok: r.ok,
      total: r.total,
      breakAtIndex: r.breakAtIndex,
      breakAtId: r.breakAtId,
    };
    if (r.ok) {
      toast.success(`链完整 ✓ 已校验 ${r.total} 条`);
    } else {
      toast.warning(`链断 ✗ 在 #${r.breakAtIndex}（id=${r.breakAtId.slice(0, 8)}…）`);
    }
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    verifying.value = false;
  }
}

function toggleExpand(id: string) {
  expanded.value[id] = !expanded.value[id];
}

function payloadJson(l: AuditLog): string {
  if (!l.payload) return '{}';
  try {
    return JSON.stringify(l.payload.toJson(), null, 2);
  } catch {
    return '{}';
  }
}

function actionBadge(a: string): string {
  if (a.startsWith('login') || a.startsWith('logout')) return 'blue';
  if (a.startsWith('task_') || a.startsWith('suite_')) return 'amber';
  if (a.startsWith('finding_')) return 'red';
  return '';
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>审计日志</h2>
        <button class="primary" :disabled="verifying" @click="runVerify">
          {{ verifying ? '校验中…' : '校验最近 500 条链完整性' }}
        </button>
      </div>
      <p class="muted">
        全部 audit 行 append-only（PG trigger 拒 UPDATE/DELETE）；每行 hash 串成单链。
        校验按钮抽样重算最近 500 行 hash，任一行被改 → 后续断链 ✗。
      </p>

      <div v-if="verifyResult" class="verify-banner" :class="verifyResult.ok ? 'ok' : 'broken'">
        <span v-if="verifyResult.ok">✓ 链完整（已扫 {{ verifyResult.total }} 条）</span>
        <span v-else>✗ 链断于 #{{ verifyResult.breakAtIndex }} id={{ verifyResult.breakAtId.slice(0, 12) }}…（共扫 {{ verifyResult.total }}）</span>
      </div>

      <div class="row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px">
        <select v-model="filterAction" :disabled="loading">
          <option v-for="opt in ACTION_OPTIONS" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
        </select>
        <input v-model="filterResourceKind" placeholder="resource_kind（task / suite / ...）"
               :disabled="loading" style="width: 200px" />
        <input v-model="filterActorUserID" placeholder="actor user_id" :disabled="loading" style="width: 240px" />
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
      <table v-if="logs.length > 0">
        <thead>
          <tr>
            <th style="width: 16px"></th>
            <th>时间</th>
            <th>actor</th>
            <th>action</th>
            <th>resource</th>
            <th>hash</th>
          </tr>
        </thead>
        <tbody>
          <template v-for="l in logs" :key="l.id">
            <tr @click="toggleExpand(l.id)" style="cursor: pointer">
              <td>{{ expanded[l.id] ? '▾' : '▸' }}</td>
              <td class="muted" :title="formatAbsoluteTime(l.createdAt)">
                {{ formatRelativeTime(l.createdAt, nowTick) }}
              </td>
              <td>
                <code v-if="l.actorUsername">{{ l.actorUsername }}</code>
                <span v-else class="muted">system</span>
              </td>
              <td><span class="badge" :class="actionBadge(l.action)">{{ l.action }}</span></td>
              <td>
                <code class="muted">{{ l.resourceKind }}</code>
                <span v-if="l.resourceId" class="muted"> / {{ l.resourceId.slice(0, 12) }}{{ l.resourceId.length > 12 ? '…' : '' }}</span>
              </td>
              <td class="sha-cell muted" :title="l.hash">{{ l.hash.slice(0, 12) }}…</td>
            </tr>
            <tr v-if="expanded[l.id]" class="expand-row">
              <td></td>
              <td colspan="5">
                <div class="kv-grid">
                  <div><span class="muted">id</span><code>{{ l.id }}</code></div>
                  <div><span class="muted">actor_user_id</span><code>{{ l.actorUserId || '—' }}</code></div>
                  <div><span class="muted">actor_ip</span><code>{{ l.actorIp || '—' }}</code></div>
                  <div><span class="muted">user_agent</span><code style="word-break: break-all">{{ l.userAgent || '—' }}</code></div>
                  <div><span class="muted">tenant_id</span><code>{{ l.tenantId }}</code></div>
                  <div><span class="muted">project_id</span><code>{{ l.projectId || '—' }}</code></div>
                  <div><span class="muted">prev_hash</span><code class="sha-cell">{{ l.prevHash }}</code></div>
                  <div><span class="muted">hash</span><code class="sha-cell">{{ l.hash }}</code></div>
                </div>
                <h4 style="margin: 12px 0 4px">payload</h4>
                <pre class="payload-block">{{ payloadJson(l) }}</pre>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      <p v-else class="muted" style="text-align: center; padding: 24px">
        暂无审计行。登录 / 任务 / 套件等关键操作会自动落审计日志。
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
.sha-cell { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
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
.verify-banner {
  margin: 8px 0 0;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
}
.verify-banner.ok { background: rgba(22, 163, 74, 0.10); color: #166534; }
.verify-banner.broken { background: rgba(239, 68, 68, 0.10); color: #991b1b; }
</style>
