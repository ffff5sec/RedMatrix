<script setup lang="ts">
// NotificationsPanel —— 通知订阅 + 投递日志（PR-S25）。
//
// 标签页：
//   - 订阅规则：CRUD + 测试投递
//   - 投递日志：最近 100 条 + status 过滤
import { ref, computed, onMounted } from 'vue';
import { Struct } from '@bufbuild/protobuf';

import { notifyClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type {
  Subscription,
  Delivery,
} from '@/gen/proto/redmatrix/notify/v1/notify_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const toast = useToast();

const tab = ref<'subs' | 'deliveries'>('subs');
const subs = ref<Subscription[]>([]);
const subsTotal = ref(0);
const dels = ref<Delivery[]>([]);
const delsTotal = ref(0);
const projects = ref<Project[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());
const filterStatus = ref('');

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

async function loadProjects() {
  try {
    const r = await tenancyClient.listProjects({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 100 });
    projects.value = r.projects;
  } catch (e) {
    // PR-S43: 不再静默；项目列表失败影响订阅 project 名称展示
    toast.warning('项目列表加载失败：' + errorMessage(e));
  }
}

async function refreshSubs() {
  loading.value = true;
  try {
    const r = await notifyClient.listSubscriptions({ page: 1, pageSize: 100 });
    subs.value = r.subscriptions;
    subsTotal.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

async function refreshDels() {
  loading.value = true;
  try {
    const r = await notifyClient.listDeliveries({
      status: filterStatus.value || undefined,
      page: 1,
      pageSize: 100,
    });
    dels.value = r.deliveries;
    delsTotal.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(async () => {
  await Promise.all([loadProjects(), refreshSubs()]);
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

// === 新建 / 编辑订阅 ===
const showCreate = ref(false);
const editing = ref<Subscription | null>(null);
const form = ref({
  projectId: '',
  name: '',
  channel: 'webhook' as 'webhook' | 'email',
  eventKinds: ['task_completed', 'task_failed', 'finding_high'] as string[],
  webhookUrl: '',
  webhookSecret: '',
  emailTo: '',
  minSeverity: '',
  enabled: true,
});
const submitting = ref(false);

const ALL_EVENT_KINDS = [
  { value: 'task_completed', label: 'task_completed（任务完成）' },
  { value: 'task_failed', label: 'task_failed（任务失败 / 取消）' },
  { value: 'finding_high', label: 'finding_high（高危漏洞）' },
];

function openCreate() {
  editing.value = null;
  form.value = {
    projectId: '',
    name: '',
    channel: 'webhook',
    eventKinds: ['task_completed', 'task_failed', 'finding_high'],
    webhookUrl: '',
    webhookSecret: '',
    emailTo: '',
    minSeverity: '',
    enabled: true,
  };
  showCreate.value = true;
}

function openEdit(s: Subscription) {
  editing.value = s;
  const config = s.config?.toJson() as Record<string, unknown> | undefined;
  const filter = s.filter?.toJson() as Record<string, unknown> | undefined;
  form.value = {
    projectId: s.projectId || '',
    name: s.name,
    channel: (s.channel as 'webhook' | 'email') || 'webhook',
    eventKinds: [...s.eventKinds],
    webhookUrl: (config?.url as string) || '',
    webhookSecret: (config?.secret as string) || '',
    emailTo: Array.isArray(config?.to) ? (config?.to as string[]).join(', ') : '',
    minSeverity: (filter?.min_severity as string) || '',
    enabled: s.enabled,
  };
  showCreate.value = true;
}

const canSubmit = computed(() => {
  if (!form.value.name || form.value.eventKinds.length === 0) return false;
  if (form.value.channel === 'webhook') return !!form.value.webhookUrl;
  if (form.value.channel === 'email') return !!form.value.emailTo;
  return false;
});

async function submit() {
  if (submitting.value || !canSubmit.value) return;
  submitting.value = true;
  try {
    const config: Record<string, unknown> = {};
    if (form.value.channel === 'webhook') {
      config.url = form.value.webhookUrl;
      if (form.value.webhookSecret) config.secret = form.value.webhookSecret;
    } else {
      config.to = form.value.emailTo
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter((s) => s);
    }
    const filter: Record<string, unknown> = {};
    if (form.value.minSeverity) filter.min_severity = form.value.minSeverity;

    if (editing.value) {
      await notifyClient.updateSubscription({
        id: editing.value.id,
        name: form.value.name,
        eventKinds: form.value.eventKinds,
        channel: form.value.channel,
        config: Struct.fromJson(config as never),
        filter: Struct.fromJson(filter as never),
        enabled: form.value.enabled,
      });
      toast.success(`订阅 ${form.value.name} 已更新`);
    } else {
      await notifyClient.createSubscription({
        projectId: form.value.projectId || undefined,
        name: form.value.name,
        eventKinds: form.value.eventKinds,
        channel: form.value.channel,
        config: Struct.fromJson(config as never),
        filter: Struct.fromJson(filter as never),
        enabled: form.value.enabled,
      });
      toast.success(`订阅 ${form.value.name} 已创建`);
    }
    showCreate.value = false;
    await refreshSubs();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function del(s: Subscription) {
  if (!confirm(`删除订阅 ${s.name}？`)) return;
  try {
    await notifyClient.deleteSubscription({ id: s.id });
    toast.success(`订阅 ${s.name} 已删除`);
    await refreshSubs();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function testSub(s: Subscription) {
  try {
    await notifyClient.testSubscription({ id: s.id });
    toast.success(`测试投递已发送（${s.name}）`);
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

function statusBadge(s: string) {
  switch (s) {
    case 'sent':    return 'green';
    case 'pending': return 'amber';
    case 'failed':  return 'amber';
    case 'dead':    return 'red';
    default:        return '';
  }
}

function kindLabel(k: string) {
  return ALL_EVENT_KINDS.find((x) => x.value === k)?.label.replace(/\s*\(.+\)$/, '') || k;
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>通知告警</h2>
        <div class="tabs">
          <button :class="{ active: tab === 'subs' }" @click="tab = 'subs'; refreshSubs()">订阅规则</button>
          <button :class="{ active: tab === 'deliveries' }" @click="tab = 'deliveries'; refreshDels()">投递日志</button>
        </div>
      </div>

      <!-- 订阅 tab -->
      <template v-if="tab === 'subs'">
        <!-- PR-S43: 后端 notify writers=SA+PA；Auditor 隐藏写按钮避免点击后才看到 PERMISSION_DENIED -->
        <div v-if="authStore.isWriter()" class="row" style="margin-bottom: 8px">
          <button class="primary" @click="openCreate">新建订阅</button>
        </div>
        <table v-if="subs.length > 0">
          <thead>
            <tr>
              <th>名称</th>
              <th>通道</th>
              <th>项目</th>
              <th>事件</th>
              <th>启用</th>
              <th>创建</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="s in subs" :key="s.id">
              <td>{{ s.name }}</td>
              <td><span class="chip">{{ s.channel }}</span></td>
              <td class="muted">
                <span v-if="s.projectId">{{ projectName.get(s.projectId) || s.projectId.slice(0, 8) }}</span>
                <span v-else class="chip cross-chip">跨项目</span>
              </td>
              <td>
                <span v-for="k in s.eventKinds" :key="k" class="chip kind-chip">{{ kindLabel(k) }}</span>
              </td>
              <td>
                <span :class="s.enabled ? 'dot dot-green' : 'dot dot-amber'" /> {{ s.enabled ? '是' : '否' }}
              </td>
              <td class="muted" :title="formatAbsoluteTime(s.createdAt)">
                {{ formatRelativeTime(s.createdAt, nowTick) }}
              </td>
              <td>
                <!-- PR-S43: 测试 / 编辑 / 删除均为写路径，Auditor 隐藏 -->
                <div v-if="authStore.isWriter()" class="row" style="gap: 4px">
                  <button class="primary" @click="testSub(s)">测试</button>
                  <button @click="openEdit(s)">编辑</button>
                  <button class="danger" @click="del(s)">删除</button>
                </div>
                <span v-else class="muted" style="font-size: 12px">只读</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted" style="text-align: center; padding: 24px">
          暂无订阅。新建一个把扫描结果推送到 Slack / 飞书 / 钉钉。
        </p>
      </template>

      <!-- 投递日志 tab -->
      <template v-else>
        <div class="row" style="margin-bottom: 8px; gap: 8px">
          <select v-model="filterStatus" :disabled="loading">
            <option value="">所有状态</option>
            <option value="pending">pending</option>
            <option value="sent">sent</option>
            <option value="failed">failed</option>
            <option value="dead">dead</option>
          </select>
          <button :disabled="loading" @click="refreshDels()">查询</button>
          <span class="muted" style="margin-left: auto">共 {{ delsTotal }} 条</span>
        </div>
        <table v-if="dels.length > 0">
          <thead>
            <tr>
              <th>事件</th>
              <th>状态</th>
              <th>尝试</th>
              <th>调度时间</th>
              <th>发送时间</th>
              <th>错误</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in dels" :key="d.id">
              <td>{{ kindLabel(d.eventKind) }}</td>
              <td><span class="badge" :class="statusBadge(d.status)">{{ d.status }}</span></td>
              <td>{{ d.attempts }}</td>
              <td class="muted" :title="formatAbsoluteTime(d.scheduledAt)">
                {{ formatRelativeTime(d.scheduledAt, nowTick) }}
              </td>
              <td class="muted" :title="d.sentAt ? formatAbsoluteTime(d.sentAt) : '—'">
                {{ d.sentAt ? formatRelativeTime(d.sentAt, nowTick) : '—' }}
              </td>
              <td class="muted err-cell">{{ d.lastError || '—' }}</td>
            </tr>
          </tbody>
        </table>
        <p v-else class="muted" style="text-align: center; padding: 24px">
          暂无投递记录。扫描完成 / 高危发现 / 测试投递会落到这里。
        </p>
      </template>
    </div>

    <!-- 新建 / 编辑订阅 modal -->
    <div v-if="showCreate" class="modal-mask">
      <div class="card modal">
        <h2>{{ editing ? '编辑订阅' : '新建订阅' }}</h2>
        <div class="form">
          <div class="form-row">
            <span class="label">名称</span>
            <input v-model="form.name" placeholder="如：Slack 全栈告警" :disabled="submitting" style="flex: 1" />
          </div>
          <div class="form-row">
            <span class="label">归属项目</span>
            <select v-model="form.projectId" :disabled="submitting || !!editing" style="flex: 1">
              <option value="">跨项目（同租户所有事件）</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="form-row">
            <span class="label">通道</span>
            <select v-model="form.channel" :disabled="submitting" style="flex: 1">
              <option value="webhook">Webhook（Slack / 飞书 / 钉钉）</option>
              <option value="email">Email（SMTP）</option>
            </select>
          </div>
          <div v-if="form.channel === 'webhook'" class="form-row">
            <span class="label">Webhook URL</span>
            <input v-model="form.webhookUrl" placeholder="https://hooks.slack.com/..." :disabled="submitting" style="flex: 1" />
          </div>
          <div v-if="form.channel === 'webhook'" class="form-row">
            <span class="label">签名密钥</span>
            <input v-model="form.webhookSecret" placeholder="可选；非空 → HMAC-SHA256 签名" :disabled="submitting" style="flex: 1" />
          </div>
          <div v-if="form.channel === 'email'" class="form-row form-row-top">
            <span class="label">收件人</span>
            <textarea v-model="form.emailTo" placeholder="逗号或换行分隔" :disabled="submitting" rows="3" style="flex: 1" />
          </div>
          <div class="form-row form-row-top">
            <span class="label">监听事件</span>
            <div style="flex: 1">
              <label v-for="k in ALL_EVENT_KINDS" :key="k.value" class="kind-check">
                <input type="checkbox" :value="k.value" v-model="form.eventKinds" />
                {{ k.label }}
              </label>
            </div>
          </div>
          <div v-if="form.eventKinds.includes('finding_high')" class="form-row">
            <span class="label">最低严重度</span>
            <select v-model="form.minSeverity" :disabled="submitting" style="flex: 1">
              <option value="">默认（high）</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          </div>
          <div class="form-row">
            <span class="label">启用</span>
            <label><input type="checkbox" v-model="form.enabled" :disabled="submitting" /> 立即开始监听事件</label>
          </div>

          <div class="row">
            <button class="primary" :disabled="submitting || !canSubmit" @click="submit">
              {{ submitting ? '保存中…' : '保存' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
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
.muted { color: var(--muted, #6b7280); }
.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
  margin-right: 4px;
}
.kind-chip { margin-bottom: 2px; display: inline-block; }
.cross-chip { background: rgba(245, 158, 11, 0.12); color: #b45309; }
.dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 4px;
}
.dot-green { background: #16a34a; }
.dot-amber { background: #d97706; }
.badge.green { background: rgba(22, 163, 74, 0.16); color: #166534; }
.badge.amber { background: rgba(245, 158, 11, 0.16); color: #92400e; }
.badge.red { background: rgba(239, 68, 68, 0.16); color: #991b1b; }
.err-cell { max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.modal-mask {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.36);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.modal {
  width: min(620px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}
.form { display: flex; flex-direction: column; gap: 12px; margin-top: 8px; }
.form-row { display: flex; align-items: center; gap: 12px; }
.form-row-top { align-items: flex-start; }
.form-row-top .label { padding-top: 6px; }
.label { width: 100px; color: var(--muted, #6b7280); font-size: 13px; }
.kind-check { display: block; margin-bottom: 4px; font-size: 13px; }
.kind-check input { margin-right: 6px; }
</style>
