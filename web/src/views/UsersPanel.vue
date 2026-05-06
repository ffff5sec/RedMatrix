<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { identityClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import type { User } from '@/gen/proto/redmatrix/identity/v1/identity_pb';

const users = ref<User[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const filterStatus = ref('');
const filterRole = ref('');
const filterKeyword = ref('');

const loading = ref(false);
const errMsg = ref('');
const successMsg = ref('');

async function refresh() {
  loading.value = true;
  errMsg.value = '';
  try {
    const r = await identityClient.listUsers({
      status: filterStatus.value || undefined,
      role: filterRole.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    users.value = r.users;
    total.value = r.total;
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

// === CreateUser ===
const showCreate = ref(false);
const newU = ref({
  username: '',
  email: '',
  role: 'PROJECT_ADMIN',
  tenantId: '',
  initialPassword: '',
});
const submitting = ref(false);
const lastTempPwd = ref<{ username: string; password: string } | null>(null);

function resetCreate() {
  newU.value = { username: '', email: '', role: 'PROJECT_ADMIN', tenantId: '', initialPassword: '' };
}

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    const r = await identityClient.createUser({
      username: newU.value.username,
      email: newU.value.email,
      role: newU.value.role,
      tenantId: newU.value.tenantId,
      initialPassword: newU.value.initialPassword || undefined,
    });
    lastTempPwd.value = {
      username: r.user?.username ?? newU.value.username,
      password: r.temporaryPassword,
    };
    showCreate.value = false;
    resetCreate();
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    submitting.value = false;
  }
}

// === per-row 操作 ===
async function enable(id: string) {
  errMsg.value = '';
  try {
    await identityClient.enableUser({ id });
    successMsg.value = '已启用';
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function disable(id: string) {
  if (!confirm('确认禁用？该用户所有 JWT 立即失效')) return;
  errMsg.value = '';
  try {
    await identityClient.disableUser({ id });
    successMsg.value = '已禁用 + token_version+1';
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function resetPwd(id: string, username: string) {
  if (!confirm('为 ' + username + ' 生成新临时密码？该用户当前 JWT 会失效。')) return;
  errMsg.value = '';
  try {
    const r = await identityClient.resetPassword({ id });
    lastTempPwd.value = { username, password: r.temporaryPassword };
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function forceLogout(id: string, username: string) {
  if (!confirm('强制登出 ' + username + '？该用户所有 JWT 立即失效（密码不变）。')) return;
  errMsg.value = '';
  try {
    await identityClient.forceLogout({ id });
    successMsg.value = `${username} token_version+1`;
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

const totalPages = () => Math.max(1, Math.ceil(total.value / pageSize.value));

function copyText(s: string) {
  navigator.clipboard?.writeText(s);
}
</script>

<template>
  <div v-if="!authStore.isSuperAdmin() && !authStore.isAuditor()" class="card">
    <p class="muted">仅 SuperAdmin / TenantAuditor 可访问。</p>
  </div>

  <template v-else>
    <div class="card">
      <h2>用户列表</h2>
      <div class="row">
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option value="active">active</option>
          <option value="disabled">disabled</option>
          <option value="pending_deletion">pending_deletion</option>
        </select>
        <select v-model="filterRole" :disabled="loading">
          <option value="">所有角色</option>
          <option value="SUPER_ADMIN">SUPER_ADMIN</option>
          <option value="PROJECT_ADMIN">PROJECT_ADMIN</option>
          <option value="TENANT_AUDITOR">TENANT_AUDITOR</option>
        </select>
        <input
          v-model="filterKeyword"
          placeholder="username / email 模糊搜索"
          :disabled="loading"
          style="width: 240px"
        />
        <button :disabled="loading" @click="page = 1; refresh()">查询</button>
        <button v-if="authStore.isSuperAdmin()" class="primary" @click="showCreate = true">
          创建用户
        </button>
      </div>

      <div v-if="errMsg" class="error">{{ errMsg }}</div>
      <div v-if="successMsg" class="success">{{ successMsg }}</div>

      <div v-if="lastTempPwd" class="info">
        <strong>临时密码（仅本次显示）·{{ lastTempPwd.username }}：</strong>
        <code class="mono" style="display: block; margin-top: 4px">{{ lastTempPwd.password }}</code>
        <button style="margin-top: 8px" @click="copyText(lastTempPwd.password)">复制</button>
        <button style="margin-left: 4px" @click="lastTempPwd = null">关闭</button>
      </div>

      <table>
        <thead>
          <tr>
            <th>用户名</th>
            <th>邮箱</th>
            <th>角色</th>
            <th>状态</th>
            <th>租户</th>
            <th>最近登录</th>
            <th v-if="authStore.isSuperAdmin()">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td>{{ u.username }}</td>
            <td>{{ u.email ?? '-' }}</td>
            <td><span class="badge blue">{{ u.role }}</span></td>
            <td>
              <span class="badge" :class="u.status === 'active' ? 'green' : 'amber'">{{ u.status }}</span>
            </td>
            <td><code>{{ u.tenantId || '—' }}</code></td>
            <td class="muted">
              {{ u.lastLoginAt ? u.lastLoginAt.toDate().toLocaleString() : '从未' }}
            </td>
            <td v-if="authStore.isSuperAdmin()">
              <div class="row" style="gap: 4px">
                <button v-if="u.status !== 'active'" @click="enable(u.id)">启用</button>
                <button v-else class="danger" @click="disable(u.id)">禁用</button>
                <button @click="resetPwd(u.id, u.username)">重置密码</button>
                <button @click="forceLogout(u.id, u.username)">强制登出</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <div class="row" style="justify-content: space-between">
        <span class="muted">共 {{ total }} 条</span>
        <div class="row">
          <button :disabled="page <= 1 || loading" @click="page--; refresh()">上一页</button>
          <span class="muted">第 {{ page }} / {{ totalPages() }} 页</span>
          <button :disabled="page >= totalPages() || loading" @click="page++; refresh()">下一页</button>
        </div>
      </div>
    </div>

    <div v-if="showCreate" class="modal-backdrop" @click.self="showCreate = false">
      <div class="modal">
        <h2>创建用户</h2>
        <div class="stack">
          <div class="row">
            <span class="label">用户名</span>
            <input v-model="newU.username" placeholder="3-32 字符，小写 / 数字 / _ / -" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">邮箱</span>
            <input v-model="newU.email" placeholder="user@example.com" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">角色</span>
            <select v-model="newU.role" :disabled="submitting">
              <option value="PROJECT_ADMIN">PROJECT_ADMIN</option>
              <option value="TENANT_AUDITOR">TENANT_AUDITOR</option>
              <option value="SUPER_ADMIN">SUPER_ADMIN</option>
            </select>
          </div>
          <div class="row">
            <span class="label">租户 ID</span>
            <input
              v-model="newU.tenantId"
              placeholder="跨租户角色（SUPER_ADMIN）留空"
              :disabled="submitting"
              style="width: 320px"
            />
          </div>
          <div class="row">
            <span class="label">初始密码</span>
            <input
              v-model="newU.initialPassword"
              type="password"
              placeholder="留空 = 服务端生成 16 字符强随机"
              :disabled="submitting"
            />
          </div>
          <p class="muted">新用户 must_change_password=true，首登必须改密。</p>
          <div class="row">
            <button class="primary" :disabled="submitting || !newU.username" @click="create">
              {{ submitting ? '创建中…' : '创建' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false; resetCreate()">取消</button>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>
