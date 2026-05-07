<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import type { Node, RegistrationToken } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const nodes = ref<Node[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const filterStatus = ref('');
const filterKeyword = ref('');

const loading = ref(false);
const errMsg = ref('');
const successMsg = ref('');

async function refresh() {
  loading.value = true;
  errMsg.value = '';
  try {
    const r = await tenancyClient.listNodes({
      tenantId: DEFAULT_TENANT_ID,
      status: filterStatus.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    nodes.value = r.nodes;
    total.value = r.total;
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// === Create ===
const showCreate = ref(false);
const newN = ref({ name: '', version: '', capabilities: '' });
const submitting = ref(false);

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    const caps = newN.value.capabilities
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    await tenancyClient.createNode({
      tenantId: DEFAULT_TENANT_ID,
      name: newN.value.name,
      version: newN.value.version,
      capabilities: caps,
    });
    showCreate.value = false;
    newN.value = { name: '', version: '', capabilities: '' };
    successMsg.value = '节点已注册（pending）';
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    submitting.value = false;
  }
}

async function enable(id: string, name: string) {
  errMsg.value = '';
  try {
    await tenancyClient.enableNode({ id });
    successMsg.value = `${name} 已启用（pending）`;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function disable(id: string, name: string) {
  if (!confirm(`禁用 ${name}？`)) return;
  errMsg.value = '';
  try {
    await tenancyClient.disableNode({ id });
    successMsg.value = `${name} 已禁用`;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function del(id: string, name: string) {
  if (!confirm(`删除节点 ${name}？该操作不可撤销（MVP 软删，名称可重新使用）。`)) return;
  errMsg.value = '';
  try {
    await tenancyClient.deleteNode({ id });
    successMsg.value = `${name} 已删除`;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

function fmt(t?: { toDate(): Date }) {
  return t ? t.toDate().toLocaleString() : '-';
}

function statusBadge(s: string) {
  switch (s) {
    case 'online': return 'green';
    case 'pending': return 'amber';
    case 'offline': return 'amber';
    case 'disabled': return 'red';
    default: return '';
  }
}

// === RegistrationToken（节点接入）===

const showTokens = ref(false);
const tokens = ref<RegistrationToken[]>([]);
const tokensLoading = ref(false);
const tokensErr = ref('');
const newToken = ref({ name: '', ttlHours: 1 });
const tokenSubmitting = ref(false);
const lastPlaintext = ref<{ name: string; plaintext: string } | null>(null);

async function refreshTokens() {
  tokensLoading.value = true;
  tokensErr.value = '';
  try {
    const r = await tenancyClient.listRegistrationTokens({ tenantId: DEFAULT_TENANT_ID });
    tokens.value = r.tokens;
  } catch (e) {
    tokensErr.value = errorMessage(e);
  } finally {
    tokensLoading.value = false;
  }
}

async function toggleTokens() {
  showTokens.value = !showTokens.value;
  if (showTokens.value) await refreshTokens();
}

async function createToken() {
  if (tokenSubmitting.value) return;
  tokenSubmitting.value = true;
  tokensErr.value = '';
  try {
    const r = await tenancyClient.createRegistrationToken({
      tenantId: DEFAULT_TENANT_ID,
      name: newToken.value.name,
      ttlSeconds: BigInt(Math.max(60, Math.min(86400, newToken.value.ttlHours * 3600))),
    });
    lastPlaintext.value = { name: newToken.value.name, plaintext: r.plaintext };
    newToken.value = { name: '', ttlHours: 1 };
    await refreshTokens();
  } catch (e) {
    tokensErr.value = errorMessage(e);
  } finally {
    tokenSubmitting.value = false;
  }
}

async function revokeToken(id: string, name: string) {
  if (!confirm(`撤销注册令牌 ${name}？已撤销不可恢复（请重新创建）。`)) return;
  tokensErr.value = '';
  try {
    await tenancyClient.revokeRegistrationToken({ id });
    await refreshTokens();
  } catch (e) {
    tokensErr.value = errorMessage(e);
  }
}

function copyText(s: string) {
  navigator.clipboard?.writeText(s);
}

function tokenStatusOf(t: RegistrationToken): { text: string; cls: string } {
  if (t.revokedAt) return { text: 'revoked', cls: 'red' };
  if (t.usedAt) return { text: 'used', cls: 'green' };
  if (t.expiresAt && t.expiresAt.toDate() < new Date()) return { text: 'expired', cls: 'amber' };
  return { text: 'pending', cls: 'amber' };
}
</script>

<template>
  <div v-if="!authStore.isSuperAdmin() && !authStore.isAuditor()" class="card">
    <p class="muted">仅 SuperAdmin / TenantAuditor 可访问。</p>
  </div>

  <template v-else>
    <div class="card">
      <div class="row" style="justify-content: space-between">
        <h2>注册令牌</h2>
        <button @click="toggleTokens">
          {{ showTokens ? '收起' : '展开' }}
        </button>
      </div>
      <p class="muted">
        SA 生成一次性令牌；真节点（Agent）首次连接时凭此换取节点身份（PR-T4-D 加 mTLS 证书）。
      </p>

      <div v-if="showTokens">
        <div v-if="tokensErr" class="error">{{ tokensErr }}</div>

        <div v-if="lastPlaintext" class="info">
          <strong>新令牌已创建（仅本次显示）·{{ lastPlaintext.name }}：</strong>
          <code class="mono" style="display: block; margin-top: 4px; word-break: break-all">{{ lastPlaintext.plaintext }}</code>
          <button style="margin-top: 8px" @click="copyText(lastPlaintext.plaintext)">复制</button>
          <button style="margin-left: 4px" @click="lastPlaintext = null">关闭</button>
        </div>

        <div v-if="authStore.isSuperAdmin()" class="row" style="margin: 12px 0">
          <input
            v-model="newToken.name"
            placeholder="令牌名（如 q1-batch）"
            :disabled="tokenSubmitting"
          />
          <input
            v-model.number="newToken.ttlHours"
            type="number"
            min="1"
            max="24"
            :disabled="tokenSubmitting"
            style="width: 80px"
          />
          <span class="muted">小时（1-24）</span>
          <button
            class="primary"
            :disabled="tokenSubmitting || !newToken.name"
            @click="createToken"
          >
            {{ tokenSubmitting ? '生成中…' : '生成令牌' }}
          </button>
        </div>

        <table v-if="tokens.length > 0">
          <thead>
            <tr>
              <th>名称</th>
              <th>状态</th>
              <th>过期</th>
              <th>已用</th>
              <th>创建</th>
              <th v-if="authStore.isSuperAdmin()"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="t in tokens" :key="t.id">
              <td>{{ t.name }}</td>
              <td>
                <span class="badge" :class="tokenStatusOf(t).cls">{{ tokenStatusOf(t).text }}</span>
              </td>
              <td class="muted">{{ fmt(t.expiresAt) }}</td>
              <td class="muted">{{ fmt(t.usedAt) }}</td>
              <td class="muted">{{ fmt(t.createdAt) }}</td>
              <td v-if="authStore.isSuperAdmin()">
                <button
                  v-if="!t.revokedAt && !t.usedAt"
                  class="danger"
                  @click="revokeToken(t.id, t.name)"
                >
                  撤销
                </button>
                <span v-else class="muted">—</span>
              </td>
            </tr>
          </tbody>
        </table>
        <p v-else-if="!tokensLoading" class="muted">尚无令牌。</p>
      </div>
    </div>

    <div class="card">
      <h2>节点</h2>
      <div class="row">
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option value="pending">pending</option>
          <option value="online">online</option>
          <option value="offline">offline</option>
          <option value="disabled">disabled</option>
        </select>
        <input
          v-model="filterKeyword"
          placeholder="按名称模糊搜索"
          :disabled="loading"
          style="width: 240px"
        />
        <button :disabled="loading" @click="page = 1; refresh()">查询</button>
        <button v-if="authStore.isSuperAdmin()" class="primary" @click="showCreate = true">
          注册节点
        </button>
      </div>

      <div v-if="errMsg" class="error">{{ errMsg }}</div>
      <div v-if="successMsg" class="success">{{ successMsg }}</div>

      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>版本</th>
            <th>能力</th>
            <th>状态</th>
            <th>最后心跳</th>
            <th>注册时间</th>
            <th v-if="authStore.isSuperAdmin()">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="n in nodes" :key="n.id">
            <td>{{ n.name }}</td>
            <td class="muted">{{ n.version || '-' }}</td>
            <td>
              <code v-if="n.capabilities.length > 0">{{ n.capabilities.join(', ') }}</code>
              <span v-else class="muted">-</span>
            </td>
            <td>
              <span class="badge" :class="statusBadge(n.status)">{{ n.status }}</span>
            </td>
            <td class="muted">{{ fmt(n.lastSeenAt) }}</td>
            <td class="muted">{{ fmt(n.createdAt) }}</td>
            <td v-if="authStore.isSuperAdmin()">
              <div class="row" style="gap: 4px">
                <button v-if="n.status === 'disabled'" @click="enable(n.id, n.name)">
                  启用
                </button>
                <button v-else @click="disable(n.id, n.name)">禁用</button>
                <button class="danger" @click="del(n.id, n.name)">删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="nodes.length === 0">
            <td colspan="7" class="muted" style="text-align: center; padding: 24px">
              暂无节点
            </td>
          </tr>
        </tbody>
      </table>

      <div class="row" style="justify-content: space-between">
        <span class="muted">共 {{ total }} 个节点</span>
        <div class="row">
          <button :disabled="page <= 1 || loading" @click="page--; refresh()">上一页</button>
          <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
          <button :disabled="page >= totalPages() || loading" @click="page++; refresh()">下一页</button>
        </div>
      </div>

      <p class="muted">
        MVP：手动注册节点。完整 RegistrationToken / mTLS 流程见 PR-T4-B/D。
      </p>
    </div>

    <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
      <div class="modal">
        <h2>注册节点</h2>
        <div class="stack">
          <div class="row">
            <span class="label">名称</span>
            <input v-model="newN.name" placeholder="租户内唯一" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">版本</span>
            <input v-model="newN.version" placeholder="可选，e.g. 1.0.0" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">能力</span>
            <input
              v-model="newN.capabilities"
              placeholder="scan:web, scan:port（逗号分隔）"
              :disabled="submitting"
              style="flex: 1"
            />
          </div>
          <p class="muted">注册后状态为 pending，等待真节点上线 / SA 手动启用。</p>
          <div class="row">
            <button class="primary" :disabled="submitting || !newN.name" @click="create">
              {{ submitting ? '创建中…' : '注册' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>
