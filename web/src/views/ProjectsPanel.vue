<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { tenancyClient, identityClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import type { Project, ProjectMember, Node } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';
import type { User } from '@/gen/proto/redmatrix/identity/v1/identity_pb';

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
    // PA 时后端按 principal.UserID 自动过滤；前端传 tenant_id 即可。
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

// === ProjectMember 管理 modal ===

const memberModalProject = ref<{ id: string; name: string } | null>(null);
const members = ref<ProjectMember[]>([]);
const eligibleUsers = ref<User[]>([]); // 同 tenant 下的 PROJECT_ADMIN
const usernameByID = ref<Record<string, string>>({});
const memberLoading = ref(false);
const memberErr = ref('');

async function openMembers(id: string, name: string) {
  memberModalProject.value = { id, name };
  memberErr.value = '';
  memberLoading.value = true;
  try {
    const [mList, uList] = await Promise.all([
      tenancyClient.listProjectMembers({ projectId: id }),
      identityClient.listUsers({ role: 'PROJECT_ADMIN', pageSize: 200 }).catch(() => ({ users: [] })),
    ]);
    members.value = mList.members;
    eligibleUsers.value = uList.users;
    const byID: Record<string, string> = {};
    for (const u of uList.users) byID[u.id] = u.username;
    usernameByID.value = byID;
  } catch (e) {
    memberErr.value = errorMessage(e);
  } finally {
    memberLoading.value = false;
  }
}

function closeMembers() {
  memberModalProject.value = null;
  members.value = [];
  eligibleUsers.value = [];
  usernameByID.value = {};
}

const selectedUserToAdd = ref('');

async function addMember() {
  if (!memberModalProject.value || !selectedUserToAdd.value) return;
  memberErr.value = '';
  try {
    await tenancyClient.addProjectMember({
      projectId: memberModalProject.value.id,
      userId: selectedUserToAdd.value,
    });
    selectedUserToAdd.value = '';
    await openMembers(memberModalProject.value.id, memberModalProject.value.name);
  } catch (e) {
    memberErr.value = errorMessage(e);
  }
}

async function removeMember(userID: string, username: string) {
  if (!memberModalProject.value) return;
  if (!confirm(`将 ${username} 从 ${memberModalProject.value.name} 移除？`)) return;
  memberErr.value = '';
  try {
    await tenancyClient.removeProjectMember({
      projectId: memberModalProject.value.id,
      userId: userID,
    });
    await openMembers(memberModalProject.value.id, memberModalProject.value.name);
  } catch (e) {
    memberErr.value = errorMessage(e);
  }
}

// === Allowed Nodes modal ===

const nodesModalProject = ref<{ id: string; name: string } | null>(null);
const allowedAllNodes = ref(true);
const allowedNodeIDs = ref<Set<string>>(new Set());
const availableNodes = ref<Node[]>([]);
const nodeNameByID = ref<Record<string, string>>({});
const nodesLoading = ref(false);
const nodesErr = ref('');

async function openAllowedNodes(id: string, name: string) {
  nodesModalProject.value = { id, name };
  nodesErr.value = '';
  nodesLoading.value = true;
  try {
    const [allowedRes, nodesRes] = await Promise.all([
      tenancyClient.getProjectAllowedNodes({ projectId: id }),
      tenancyClient
        .listNodes({ tenantId: DEFAULT_TENANT_ID, pageSize: 200 })
        .catch(() => ({ nodes: [] as Node[] })),
    ]);
    allowedAllNodes.value = allowedRes.allNodes;
    allowedNodeIDs.value = new Set(allowedRes.nodeIds);
    availableNodes.value = nodesRes.nodes;
    const byID: Record<string, string> = {};
    for (const n of nodesRes.nodes) byID[n.id] = n.name;
    nodeNameByID.value = byID;
  } catch (e) {
    nodesErr.value = errorMessage(e);
  } finally {
    nodesLoading.value = false;
  }
}

function closeAllowedNodes() {
  nodesModalProject.value = null;
  availableNodes.value = [];
  allowedNodeIDs.value = new Set();
  nodeNameByID.value = {};
}

function toggleNode(id: string) {
  // 切到显式白名单模式：取消 ALL，开始按 NodeIDs 编辑
  allowedAllNodes.value = false;
  const next = new Set(allowedNodeIDs.value);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  allowedNodeIDs.value = next;
}

function resetToAllNodes() {
  allowedAllNodes.value = true;
  allowedNodeIDs.value = new Set();
}

async function saveAllowedNodes() {
  if (!nodesModalProject.value) return;
  nodesErr.value = '';
  try {
    const ids = allowedAllNodes.value ? [] : Array.from(allowedNodeIDs.value);
    await tenancyClient.setProjectAllowedNodes({
      projectId: nodesModalProject.value.id,
      nodeIds: ids,
    });
    successMsg.value = '可用节点已更新';
    closeAllowedNodes();
  } catch (e) {
    nodesErr.value = errorMessage(e);
  }
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
            <th v-if="authStore.isSuperAdmin() || (authStore.isAuthed() && !authStore.isAuditor())">操作</th>
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
                <button @click="openMembers(p.id, p.name)">成员</button>
                <button @click="openAllowedNodes(p.id, p.name)">节点</button>
                <button v-if="p.status === 'active'" @click="archive(p.id, p.name)">
                  归档
                </button>
                <button v-else @click="unarchive(p.id, p.name)">恢复</button>
                <button class="danger" @click="del(p.id, p.name)">删除</button>
              </div>
            </td>
            <td v-else-if="authStore.isAuthed() && !authStore.isAuditor()">
              <div class="row" style="gap: 4px">
                <button @click="openMembers(p.id, p.name)">成员</button>
                <button @click="openAllowedNodes(p.id, p.name)">节点</button>
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

    <div v-if="memberModalProject" class="modal-backdrop" @click.self="closeMembers">
      <div class="modal" style="min-width: 480px; max-width: 640px">
        <div class="row" style="justify-content: space-between">
          <h2>项目成员 · {{ memberModalProject.name }}</h2>
          <button @click="closeMembers">关闭</button>
        </div>
        <div v-if="memberErr" class="error">{{ memberErr }}</div>
        <p v-if="memberLoading" class="muted">加载中…</p>

        <table v-else>
          <thead>
            <tr>
              <th>用户名</th>
              <th>加入时间</th>
              <th v-if="authStore.isSuperAdmin()"></th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="m in members" :key="m.userId">
              <td>{{ usernameByID[m.userId] ?? m.userId }}</td>
              <td class="muted">{{ fmt(m.addedAt) }}</td>
              <td v-if="authStore.isSuperAdmin()">
                <button class="danger" @click="removeMember(m.userId, usernameByID[m.userId] ?? m.userId)">
                  移除
                </button>
              </td>
            </tr>
            <tr v-if="members.length === 0">
              <td colspan="3" class="muted" style="text-align: center; padding: 16px">
                暂无成员
              </td>
            </tr>
          </tbody>
        </table>

        <div v-if="authStore.isSuperAdmin()" class="row" style="margin-top: 12px">
          <span class="label">添加</span>
          <select v-model="selectedUserToAdd" style="flex: 1; min-width: 0">
            <option value="">选择 ProjectAdmin 用户…</option>
            <option v-for="u in eligibleUsers" :key="u.id" :value="u.id">
              {{ u.username }} · {{ u.email ?? '-' }}
            </option>
          </select>
          <button class="primary" :disabled="!selectedUserToAdd" @click="addMember">
            添加
          </button>
        </div>
        <p v-if="authStore.isSuperAdmin()" class="muted">
          仅 PROJECT_ADMIN 角色可加入项目（schema 强制）；先在"用户管理"创建。
        </p>
      </div>
    </div>

    <div v-if="nodesModalProject" class="modal-backdrop" @click.self="closeAllowedNodes">
      <div class="modal" style="min-width: 480px; max-width: 640px">
        <div class="row" style="justify-content: space-between">
          <h2>可用节点 · {{ nodesModalProject.name }}</h2>
          <button @click="closeAllowedNodes">关闭</button>
        </div>
        <div v-if="nodesErr" class="error">{{ nodesErr }}</div>
        <p v-if="nodesLoading" class="muted">加载中…</p>

        <div v-else>
          <div class="row" style="margin-bottom: 8px">
            <label>
              <input
                type="radio"
                :checked="allowedAllNodes"
                @change="resetToAllNodes"
              />
              所有节点可用（ALL 默认）
            </label>
            <label style="margin-left: 16px">
              <input
                type="radio"
                :checked="!allowedAllNodes"
                @change="allowedAllNodes = false"
              />
              白名单
            </label>
          </div>

          <div v-if="!allowedAllNodes">
            <div v-if="availableNodes.length === 0" class="muted">
              租户下暂无节点。请先到"节点"Tab 注册。
            </div>
            <div v-else class="stack" style="max-height: 280px; overflow: auto; border: 1px solid #e5e7eb; padding: 8px; border-radius: 4px">
              <label v-for="n in availableNodes" :key="n.id" class="row" style="cursor: pointer">
                <input
                  type="checkbox"
                  :checked="allowedNodeIDs.has(n.id)"
                  @change="toggleNode(n.id)"
                />
                <span class="mono">{{ n.name }}</span>
                <span class="badge" :style="{ marginLeft: '8px' }">{{ n.status }}</span>
              </label>
            </div>
            <p class="muted" style="margin-top: 8px">
              已选 {{ allowedNodeIDs.size }} / {{ availableNodes.length }} 个节点。
              空白名单 = 任何节点都不允许（不同于 ALL）。
            </p>
          </div>

          <div v-else class="info">
            当前所有节点都可用。若切换到白名单，仅勾选的节点可被该项目使用。
          </div>

          <div class="row" style="margin-top: 12px">
            <button v-if="authStore.isSuperAdmin() || authStore.isAuthed()" class="primary" @click="saveAllowedNodes">
              保存
            </button>
            <button @click="closeAllowedNodes">取消</button>
          </div>
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
