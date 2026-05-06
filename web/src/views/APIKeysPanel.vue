<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { identityClient } from '@/api/transport';
import { errorMessage } from '@/util/error';
import type { APIKey } from '@/gen/proto/redmatrix/identity/v1/identity_pb';

const keys = ref<APIKey[]>([]);
const loading = ref(false);
const errMsg = ref('');

async function refresh() {
  loading.value = true;
  errMsg.value = '';
  try {
    const r = await identityClient.listAPIKeys({});
    keys.value = r.keys;
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// === Create ===
const showCreate = ref(false);
const newName = ref('');
const newScopes = ref('');
const submitting = ref(false);
// 创建后一次性返的明文：突出显示 + 只能复制一次
const lastSecret = ref('');

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    const scopes = newScopes.value
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const r = await identityClient.createAPIKey({
      name: newName.value,
      scopes,
    });
    lastSecret.value = r.secret;
    newName.value = '';
    newScopes.value = '';
    showCreate.value = false;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    submitting.value = false;
  }
}

async function revoke(id: string) {
  if (!confirm('确认撤销此 API Key？此操作不可撤销。')) return;
  errMsg.value = '';
  try {
    await identityClient.revokeAPIKey({ id });
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

function copyText(s: string) {
  navigator.clipboard?.writeText(s);
}

function fmt(t?: { toDate(): Date }) {
  return t ? t.toDate().toLocaleString() : '-';
}

interface KeyStatusView { text: string; cls: string }

function statusOf(revokedAt?: { toDate(): Date }, expiresAt?: { toDate(): Date }): KeyStatusView {
  if (revokedAt) return { text: 'revoked', cls: 'red' };
  if (expiresAt && expiresAt.toDate() < new Date()) return { text: 'expired', cls: 'amber' };
  return { text: 'active', cls: 'green' };
}
</script>

<template>
  <div class="card">
    <div class="row" style="justify-content: space-between">
      <h2>API Keys</h2>
      <div class="row">
        <button :disabled="loading" @click="refresh">刷新</button>
        <button class="primary" @click="showCreate = true">创建 API Key</button>
      </div>
    </div>

    <div v-if="errMsg" class="error">{{ errMsg }}</div>

    <div v-if="lastSecret" class="info">
      <strong>新 API Key 已创建（仅本次显示）：</strong>
      <code class="mono" style="display: block; margin-top: 4px; word-break: break-all">{{ lastSecret }}</code>
      <button style="margin-top: 8px" @click="copyText(lastSecret)">复制</button>
      <button style="margin-left: 4px" @click="lastSecret = ''">关闭</button>
    </div>

    <table v-if="keys.length > 0">
      <thead>
        <tr>
          <th>Name</th>
          <th>Prefix</th>
          <th>Scopes</th>
          <th>Status</th>
          <th>Created</th>
          <th>Last used</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="k in keys" :key="k.id">
          <td>{{ k.name }}</td>
          <td><code>{{ k.keyPrefix }}</code></td>
          <td>
            <span v-if="k.scopes.length === 0" class="muted">(继承用户)</span>
            <code v-else>{{ k.scopes.join(', ') }}</code>
          </td>
          <td>
            <span class="badge" :class="statusOf(k.revokedAt, k.expiresAt).cls">
              {{ statusOf(k.revokedAt, k.expiresAt).text }}
            </span>
          </td>
          <td class="muted">{{ fmt(k.createdAt) }}</td>
          <td class="muted">{{ fmt(k.lastUsedAt) }}</td>
          <td>
            <button v-if="!k.revokedAt" class="danger" @click="revoke(k.id)">撤销</button>
            <span v-else class="muted">—</span>
          </td>
        </tr>
      </tbody>
    </table>
    <p v-else class="muted">尚无 API Key。</p>
  </div>

  <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
    <div class="modal">
      <h2>创建 API Key</h2>
      <div class="stack">
        <div class="row">
          <span class="label">名称</span>
          <input v-model="newName" placeholder="ci-bot" :disabled="submitting" />
        </div>
        <div class="row">
          <span class="label">Scopes</span>
          <input
            v-model="newScopes"
            placeholder="scan:read, asset:write（逗号分隔，留空 = 继承）"
            :disabled="submitting"
            style="flex: 1"
          />
        </div>
        <p class="muted">完整密钥仅在创建时一次性返回；遗失需重建。</p>
        <div class="row">
          <button class="primary" :disabled="submitting || !newName" @click="create">
            {{ submitting ? '创建中…' : '创建' }}
          </button>
          <button :disabled="submitting" @click="showCreate = false">取消</button>
        </div>
      </div>
    </div>
  </div>
</template>
