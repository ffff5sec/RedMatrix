<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { tenancyClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const projects = ref<Project[]>([]);
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
    const r = await tenancyClient.listProjects({
      tenantId: DEFAULT_TENANT_ID,
      status: filterStatus.value || undefined,
      keyword: filterKeyword.value || undefined,
      page: page.value,
      pageSize: pageSize.value,
    });
    projects.value = r.projects;
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
const newP = ref({ name: '', description: '' });
const submitting = ref(false);

async function create() {
  if (submitting.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    await tenancyClient.createProject({
      tenantId: DEFAULT_TENANT_ID,
      name: newP.value.name,
      description: newP.value.description,
    });
    showCreate.value = false;
    newP.value = { name: '', description: '' };
    successMsg.value = '项目已创建';
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    submitting.value = false;
  }
}

// === per-row 操作 ===

async function archive(id: string, name: string) {
  if (!confirm(`归档项目 ${name}？归档后不可修改，可解除归档。`)) return;
  errMsg.value = '';
  try {
    await tenancyClient.archiveProject({ id });
    successMsg.value = `${name} 已归档`;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function unarchive(id: string, name: string) {
  errMsg.value = '';
  try {
    await tenancyClient.unarchiveProject({ id });
    successMsg.value = `${name} 已恢复`;
    await refresh();
  } catch (e) {
    errMsg.value = errorMessage(e);
  }
}

async function del(id: string, name: string) {
  if (!confirm(`删除项目 ${name}？该操作不可撤销（MVP 软删，名称可重新使用）。`)) return;
  errMsg.value = '';
  try {
    await tenancyClient.deleteProject({ id });
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
</script>

<template>
  <div v-if="!authStore.isSuperAdmin() && !authStore.isAuditor()" class="card">
    <p class="muted">仅 SuperAdmin / TenantAuditor 可访问。</p>
  </div>

  <template v-else>
    <div class="card">
      <h2>项目</h2>
      <div class="row">
        <select v-model="filterStatus" :disabled="loading">
          <option value="">所有状态</option>
          <option value="active">active</option>
          <option value="archived">archived</option>
        </select>
        <input
          v-model="filterKeyword"
          placeholder="按名称模糊搜索"
          :disabled="loading"
          style="width: 240px"
        />
        <button :disabled="loading" @click="page = 1; refresh()">查询</button>
        <button v-if="authStore.isSuperAdmin()" class="primary" @click="showCreate = true">
          新建项目
        </button>
      </div>

      <div v-if="errMsg" class="error">{{ errMsg }}</div>
      <div v-if="successMsg" class="success">{{ successMsg }}</div>

      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>状态</th>
            <th>描述</th>
            <th>创建时间</th>
            <th>归档时间</th>
            <th v-if="authStore.isSuperAdmin()">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in projects" :key="p.id">
            <td>{{ p.name }}</td>
            <td>
              <span class="badge" :class="p.status === 'active' ? 'green' : 'amber'">
                {{ p.status }}
              </span>
            </td>
            <td class="muted">{{ p.description || '-' }}</td>
            <td class="muted">{{ fmt(p.createdAt) }}</td>
            <td class="muted">{{ fmt(p.archivedAt) }}</td>
            <td v-if="authStore.isSuperAdmin()">
              <div class="row" style="gap: 4px">
                <button v-if="p.status === 'active'" @click="archive(p.id, p.name)">
                  归档
                </button>
                <button v-else @click="unarchive(p.id, p.name)">恢复</button>
                <button class="danger" @click="del(p.id, p.name)">删除</button>
              </div>
            </td>
          </tr>
          <tr v-if="projects.length === 0">
            <td colspan="6" class="muted" style="text-align: center; padding: 24px">
              暂无项目
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
        <h2>新建项目</h2>
        <div class="stack">
          <div class="row">
            <span class="label">名称</span>
            <input v-model="newP.name" placeholder="租户内唯一" :disabled="submitting" />
          </div>
          <div class="row">
            <span class="label">描述</span>
            <input
              v-model="newP.description"
              placeholder="可选"
              :disabled="submitting"
              style="width: 320px"
            />
          </div>
          <p class="muted">tenant_id 自动注入默认 account（00000000-...-000001）。</p>
          <div class="row">
            <button class="primary" :disabled="submitting || !newP.name" @click="create">
              {{ submitting ? '创建中…' : '创建' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
        </div>
      </div>
    </div>
  </template>
</template>
