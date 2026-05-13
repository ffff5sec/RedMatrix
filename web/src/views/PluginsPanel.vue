<script setup lang="ts">
// PluginsPanel —— 插件包仓库（PR-S28；仅 SA）。
//
// 视图：
//   - 包列表 (slug × version × platform)；启用/禁用切换；deprecate
//   - 上传 modal: slug/version/platform/description + file 选择
//   - 签名 key 区：仅展示当前公钥（agent 启动期一次性拉缓存）
import { ref, computed, onMounted } from 'vue';

import { pluginPackageClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { PluginPackage, SigningKey } from '@/gen/proto/redmatrix/pluginpkg/v1/pluginpkg_pb';

const toast = useToast();

const packages = ref<PluginPackage[]>([]);
const total = ref(0);
const keys = ref<SigningKey[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());

const filterSlug = ref('');
const filterPlatform = ref('');

async function refresh() {
  loading.value = true;
  try {
    const r = await pluginPackageClient.listPackages({
      slug: filterSlug.value || undefined,
      platform: filterPlatform.value || undefined,
      page: 1,
      pageSize: 100,
    });
    packages.value = r.packages;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

async function loadKeys() {
  try {
    const r = await pluginPackageClient.listSigningKeys({});
    keys.value = r.keys;
  } catch (e) {
    // PR-S43: 不再静默；签名 key 拉取失败影响插件信任视图，需告知用户
    toast.warning('签名密钥加载失败：' + errorMessage(e));
  }
}

onMounted(async () => {
  await Promise.all([refresh(), loadKeys()]);
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

// === 上传 modal ===
const showUpload = ref(false);
const upload = ref({
  slug: '',
  version: '',
  platform: 'linux_amd64',
  description: '',
  fileBytes: null as Uint8Array | null,
  fileName: '',
});
const submitting = ref(false);

const canSubmit = computed(
  () => !!upload.value.slug && !!upload.value.version && !!upload.value.platform && !!upload.value.fileBytes,
);

function openUpload() {
  upload.value = {
    slug: '',
    version: '',
    platform: 'linux_amd64',
    description: '',
    fileBytes: null,
    fileName: '',
  };
  showUpload.value = true;
}

async function onFileChange(ev: Event) {
  const target = ev.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;
  const buf = await file.arrayBuffer();
  upload.value.fileBytes = new Uint8Array(buf);
  upload.value.fileName = file.name;
}

async function doUpload() {
  if (!canSubmit.value || submitting.value || !upload.value.fileBytes) return;
  submitting.value = true;
  try {
    await pluginPackageClient.uploadPackage({
      slug: upload.value.slug,
      version: upload.value.version,
      platform: upload.value.platform,
      description: upload.value.description,
      binary: upload.value.fileBytes,
    });
    toast.success(`${upload.value.slug}@${upload.value.version} 已上传`);
    showUpload.value = false;
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function toggleActive(p: PluginPackage) {
  try {
    await pluginPackageClient.setPackageActive({ id: p.id, active: !p.isActive });
    toast.success(p.isActive ? '已禁用' : '已启用');
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function doDeprecate(p: PluginPackage) {
  if (!confirm(`废弃 ${p.slug}@${p.version}/${p.platform}？agent 将不再拉取此版本。`)) return;
  try {
    await pluginPackageClient.deprecatePackage({ id: p.id });
    toast.warning(`${p.slug}@${p.version} 已废弃`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

function formatSize(b: bigint | number): string {
  const n = typeof b === 'bigint' ? Number(b) : b;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / 1024 / 1024).toFixed(2)} MiB`;
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>插件库</h2>
        <!-- PR-S43: 与后端 saOnly 对齐；Auditor 看到但点击会 PERMISSION_DENIED -->
        <button v-if="authStore.isSuperAdmin()" class="primary" @click="openUpload">上传新版本</button>
      </div>
      <p class="muted">
        SA 上传插件二进制（agent 拉取 + ed25519 签名校验）。同 slug/version/platform 唯一。
      </p>

      <div class="row" style="flex-wrap: wrap; gap: 8px; margin-top: 8px">
        <input v-model="filterSlug" placeholder="按 slug 过滤" style="width: 180px" :disabled="loading" />
        <select v-model="filterPlatform" :disabled="loading">
          <option value="">所有平台</option>
          <option value="linux_amd64">linux_amd64</option>
          <option value="linux_arm64">linux_arm64</option>
          <option value="darwin_amd64">darwin_amd64</option>
          <option value="darwin_arm64">darwin_arm64</option>
          <option value="windows_amd64">windows_amd64</option>
        </select>
        <button :disabled="loading" @click="refresh()">查询</button>
        <span class="muted" style="margin-left: auto">共 {{ total }} 个版本</span>
      </div>

      <table v-if="packages.length > 0" style="margin-top: 12px">
        <thead>
          <tr>
            <th>slug</th>
            <th>version</th>
            <th>platform</th>
            <th>大小</th>
            <th>sha256</th>
            <th>启用</th>
            <th>上传</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in packages" :key="p.id" :class="{ deprecated: !!p.deprecatedAt }">
            <td>{{ p.slug }}</td>
            <td>{{ p.version }}</td>
            <td>{{ p.platform }}</td>
            <td class="muted">{{ formatSize(p.sizeBytes) }}</td>
            <td class="muted sha-cell" :title="p.sha256">{{ p.sha256.slice(0, 12) }}…</td>
            <td>
              <span :class="p.isActive ? 'dot dot-green' : 'dot dot-amber'" />
              {{ p.isActive ? '是' : '否' }}
            </td>
            <td class="muted" :title="formatAbsoluteTime(p.uploadedAt)">
              {{ formatRelativeTime(p.uploadedAt, nowTick) }}
            </td>
            <td>
              <div class="row" style="gap: 4px">
                <!-- PR-S43: SA-only 写操作 -->
                <button v-if="authStore.isSuperAdmin() && !p.deprecatedAt" @click="toggleActive(p)">
                  {{ p.isActive ? '禁用' : '启用' }}
                </button>
                <button v-if="authStore.isSuperAdmin() && !p.deprecatedAt" class="danger" @click="doDeprecate(p)">废弃</button>
                <span v-if="p.deprecatedAt" class="muted" style="font-size: 12px">已废弃</span>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted" style="text-align: center; padding: 24px">
        暂无插件包。点 "上传新版本" 上传第一个二进制。
      </p>
    </div>

    <div class="card" v-if="keys.length > 0">
      <h2>签名公钥</h2>
      <p class="muted">
        Agent 启动期拉取此列表缓存；ed25519 验证插件签名。
      </p>
      <table>
        <thead>
          <tr>
            <th>key_id</th>
            <th>public_key</th>
            <th>说明</th>
            <th>创建</th>
            <th>状态</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="k in keys" :key="k.id">
            <td><code>{{ k.keyId }}</code></td>
            <td class="muted sha-cell" :title="k.publicKey">{{ k.publicKey.slice(0, 24) }}…</td>
            <td class="muted">{{ k.description || '—' }}</td>
            <td class="muted" :title="formatAbsoluteTime(k.createdAt)">
              {{ formatRelativeTime(k.createdAt, nowTick) }}
            </td>
            <td>
              <span class="badge green" v-if="!k.revokedAt">激活</span>
              <span class="badge red" v-else>已吊销</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 上传 modal -->
    <div v-if="showUpload" class="modal-mask">
      <div class="card modal">
        <h2>上传插件版本</h2>
        <div class="form">
          <div class="form-row">
            <span class="label">slug</span>
            <input v-model="upload.slug" placeholder="如 subfinder / httpx / nuclei" :disabled="submitting" style="flex: 1" />
          </div>
          <div class="form-row">
            <span class="label">version</span>
            <input v-model="upload.version" placeholder="如 2.6.3" :disabled="submitting" style="flex: 1" />
          </div>
          <div class="form-row">
            <span class="label">platform</span>
            <select v-model="upload.platform" :disabled="submitting" style="flex: 1">
              <option value="linux_amd64">linux_amd64</option>
              <option value="linux_arm64">linux_arm64</option>
              <option value="darwin_amd64">darwin_amd64</option>
              <option value="darwin_arm64">darwin_arm64</option>
              <option value="windows_amd64">windows_amd64</option>
            </select>
          </div>
          <div class="form-row">
            <span class="label">描述</span>
            <input v-model="upload.description" placeholder="可选；如 changelog 摘要" :disabled="submitting" style="flex: 1" />
          </div>
          <div class="form-row">
            <span class="label">二进制</span>
            <div style="flex: 1">
              <input type="file" @change="onFileChange" :disabled="submitting" />
              <p v-if="upload.fileName" class="muted" style="font-size: 12px; margin-top: 4px">
                {{ upload.fileName }} ({{ formatSize(upload.fileBytes?.length || 0) }})
              </p>
              <p class="muted" style="font-size: 12px; margin-top: 4px">
                上传后 server 算 sha256 + ed25519 签名，agent 校验后才安装。
              </p>
            </div>
          </div>

          <div class="row">
            <button class="primary" :disabled="submitting || !canSubmit" @click="doUpload">
              {{ submitting ? '上传中…' : '上传' }}
            </button>
            <button :disabled="submitting" @click="showUpload = false">取消</button>
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
.muted { color: var(--muted, #6b7280); }
.dot {
  display: inline-block;
  width: 8px; height: 8px;
  border-radius: 50%;
  margin-right: 4px;
}
.dot-green { background: #16a34a; }
.dot-amber { background: #d97706; }
.sha-cell { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.badge.green { background: rgba(22, 163, 74, 0.16); color: #166534; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
.badge.red { background: rgba(239, 68, 68, 0.16); color: #991b1b; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
.deprecated { opacity: 0.5; }
.modal-mask {
  position: fixed; inset: 0;
  background: rgba(0, 0, 0, 0.36);
  display: flex; align-items: center; justify-content: center;
  z-index: 100;
}
.modal {
  width: min(560px, calc(100vw - 32px));
  max-height: calc(100vh - 32px);
  overflow: auto;
}
.form { display: flex; flex-direction: column; gap: 12px; margin-top: 8px; }
.form-row { display: flex; align-items: center; gap: 12px; }
.label { width: 80px; color: var(--muted, #6b7280); font-size: 13px; }
</style>
