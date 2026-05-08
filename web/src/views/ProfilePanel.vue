<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { identityClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import { useToast } from '@/composables/useToast';
import type { User } from '@/gen/proto/redmatrix/identity/v1/identity_pb';

const emit = defineEmits<{ (e: 'loggedOut'): void }>();
const toast = useToast();

const user = ref<User | null>(null);
const loading = ref(false);

async function refresh() {
  loading.value = true;
  try {
    const r = await identityClient.getCurrentUser({});
    user.value = r.user ?? null;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// === ChangePassword ===
const showChangePwd = ref(false);
const cur = ref('');
const nw = ref('');
const cpSubmitting = ref(false);

async function changePwd() {
  if (cpSubmitting.value) return;
  cpSubmitting.value = true;
  try {
    await identityClient.changePassword({
      currentPassword: cur.value,
      newPassword: nw.value,
    });
    toast.success('改密成功；JWT 已失效，下次操作会自动登出。');
    showChangePwd.value = false;
    cur.value = '';
    nw.value = '';
    // 改密后旧 JWT 失效；下次任何 RPC 触发 watchdog 清 token
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    cpSubmitting.value = false;
  }
}

// === Logout / LogoutAllSessions ===

async function logout() {
  try {
    await identityClient.logout({});
  } catch (e) {
    // 仍清本地，避免登出后留死 token
    toast.error(errorMessage(e));
  }
  authStore.clear();
  emit('loggedOut');
}

async function logoutAll() {
  try {
    await identityClient.logoutAllSessions({});
    toast.warning('已请求登出全部会话；本会话也将失效。');
    authStore.clear();
    emit('loggedOut');
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
</script>

<template>
  <div class="card">
    <h2>当前用户</h2>
    <button :disabled="loading" @click="refresh">{{ loading ? '加载中…' : '刷新 GetCurrentUser' }}</button>

    <div v-if="user" class="stack" style="margin-top: 12px">
      <div class="row"><span class="label">ID</span><code>{{ user.id }}</code></div>
      <div class="row"><span class="label">用户名</span>{{ user.username }}</div>
      <div class="row"><span class="label">邮箱</span>{{ user.email ?? '-' }}</div>
      <div class="row"><span class="label">角色</span><span class="badge blue">{{ user.role }}</span></div>
      <div class="row"><span class="label">状态</span>
        <span class="badge" :class="user.status === 'active' ? 'green' : 'amber'">{{ user.status }}</span>
      </div>
      <div class="row"><span class="label">租户</span><code>{{ user.tenantId || '(SuperAdmin 无租户)' }}</code></div>
      <div v-if="user.lastLoginAt" class="row">
        <span class="label">上次登录</span>{{ user.lastLoginAt.toDate().toLocaleString() }}
      </div>
    </div>
  </div>

  <div class="card">
    <h2>密码与会话</h2>
    <div class="row">
      <button @click="showChangePwd = true">改密</button>
      <button @click="logout">登出当前会话（Logout）</button>
      <button class="danger" @click="logoutAll">登出全部会话（LogoutAllSessions）</button>
    </div>
    <p class="muted" style="margin-top: 8px">
      改密 / LogoutAllSessions 会触发 token_version++，所有现存 JWT 立即失效。
    </p>
  </div>

  <div v-if="showChangePwd" class="modal-backdrop" @click.self="showChangePwd = false">
    <div class="modal">
      <h2>修改密码</h2>
      <div class="stack">
        <div class="row">
          <span class="label">当前密码</span>
          <input v-model="cur" type="password" :disabled="cpSubmitting" />
        </div>
        <div class="row">
          <span class="label">新密码</span>
          <input v-model="nw" type="password" :disabled="cpSubmitting" />
        </div>
        <p class="muted">新密码至少 12 字符，且不可与当前相同。</p>
        <div class="row">
          <button class="primary" :disabled="cpSubmitting || !cur || !nw" @click="changePwd">
            {{ cpSubmitting ? '提交中…' : '确认修改' }}
          </button>
          <button :disabled="cpSubmitting" @click="showChangePwd = false">取消</button>
        </div>
      </div>
    </div>
  </div>
</template>
