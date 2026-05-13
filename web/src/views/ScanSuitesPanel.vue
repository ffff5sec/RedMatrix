<script setup lang="ts">
// ScanSuitesPanel —— 扫描套件管理（PR-S23）。
//
// 范围：列 / 创建 / 删除套件 + 在套件上"一键运行"触发 RunSuite。
import { ref, computed, onMounted, watch } from 'vue';

import { scanClient, tenancyClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { formatRelativeTime, formatAbsoluteTime } from '@/util/relativeTime';
import type { ScanSuite } from '@/gen/proto/redmatrix/scan/v1/scan_pb';
import type { Project } from '@/gen/proto/redmatrix/tenancy/v1/tenancy_pb';
import { useRouter } from 'vue-router';

const DEFAULT_TENANT_ID = '00000000-0000-0000-0000-000000000001';

const toast = useToast();
const router = useRouter();
const suites = ref<ScanSuite[]>([]);
const total = ref(0);
const projects = ref<Project[]>([]);
const loading = ref(false);
const nowTick = ref(Date.now());

async function refresh() {
  loading.value = true;
  try {
    const r = await scanClient.listScanSuites({ page: 1, pageSize: 100 });
    suites.value = r.suites;
    total.value = r.total;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

async function loadProjects() {
  try {
    const r = await tenancyClient.listProjects({ tenantId: DEFAULT_TENANT_ID, page: 1, pageSize: 100 });
    projects.value = r.projects;
  } catch {
    // 忽略
  }
}

onMounted(async () => {
  await Promise.all([loadProjects(), refresh()]);
  setInterval(() => (nowTick.value = Date.now()), 1000);
});

const projectName = computed(() => {
  const m = new Map<string, string>();
  for (const p of projects.value) m.set(p.id, p.name);
  return m;
});

// === 创建套件 ===
const showCreate = ref(false);
const newSuite = ref({
  projectId: '', // 空 = 跨项目套件
  name: '',
  kindsSelected: ['port_scan', 'subdomain', 'fingerprint', 'vuln_scan'],
  targetKind: 'host',
  scheduleKind: 'immediate' as 'immediate' | 'cron',
  cronExpr: '0 2 * * *',
  defaultTargetsRaw: '',
});
const submitting = ref(false);

const ALL_KINDS = [
  { value: 'port_scan',   label: '端口扫描 (nmap)' },
  { value: 'subdomain',   label: '子域名 (subfinder)' },
  { value: 'fingerprint', label: '指纹识别 (httpx)' },
  { value: 'web_crawl',   label: '网页爬取 (httpx)' },
  { value: 'vuln_scan',   label: '漏洞扫描 (nuclei)' },
];

async function createSuite() {
  if (submitting.value) return;
  if (!newSuite.value.name || newSuite.value.kindsSelected.length === 0) {
    toast.error('套件名 + 至少 1 个 kind 必填');
    return;
  }
  const defaultTargets = parseTargets(newSuite.value.defaultTargetsRaw);
  if (newSuite.value.scheduleKind === 'cron') {
    if (!newSuite.value.cronExpr.trim()) {
      toast.error('cron 模式必须填 cron_expr');
      return;
    }
    if (defaultTargets.length === 0) {
      toast.error('cron 模式必须填 default_targets 至少 1 个');
      return;
    }
    if (!newSuite.value.projectId) {
      toast.error('cron 套件必须指定项目（cron 触发时需上下文）');
      return;
    }
  }
  submitting.value = true;
  try {
    await scanClient.createScanSuite({
      projectId: newSuite.value.projectId || undefined,
      name: newSuite.value.name,
      kinds: newSuite.value.kindsSelected,
      targetKind: newSuite.value.targetKind,
      scheduleKind: newSuite.value.scheduleKind,
      cronExpr: newSuite.value.cronExpr,
      defaultTargets,
    });
    toast.success(`套件 ${newSuite.value.name} 已创建`);
    showCreate.value = false;
    newSuite.value = {
      projectId: '', name: '',
      kindsSelected: ['port_scan', 'subdomain', 'fingerprint', 'vuln_scan'],
      targetKind: 'host',
      scheduleKind: 'immediate', cronExpr: '0 2 * * *', defaultTargetsRaw: '',
    };
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function delSuite(s: ScanSuite) {
  if (!confirm(`删除套件 ${s.name}？已生成的 run / task 不受影响。`)) return;
  try {
    await scanClient.deleteScanSuite({ id: s.id });
    toast.success(`套件 ${s.name} 已删除`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

// === 运行套件 ===
const showRun = ref(false);
const runForm = ref({
  suiteId: '',
  suiteName: '',
  projectId: '',
  targetsRaw: '',
});

function openRun(s: ScanSuite) {
  runForm.value = {
    suiteId: s.id,
    suiteName: s.name,
    projectId: s.projectId || '',
    targetsRaw: '',
  };
  showRun.value = true;
}

function parseTargets(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const line of raw.split(/[\n,]/)) {
    const s = line.trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

const runTargetsParsed = computed(() => parseTargets(runForm.value.targetsRaw));

// === PR-S24 展开预览 ===
const expandPreview = ref<{
  total: number;
  truncated: boolean;
  maxExpansion: number;
  loading: boolean;
  error: string;
} | null>(null);
let expandPreviewTimer: ReturnType<typeof setTimeout> | null = null;

watch(runTargetsParsed, (parsed) => {
  if (expandPreviewTimer) clearTimeout(expandPreviewTimer);
  if (parsed.length === 0) {
    expandPreview.value = null;
    return;
  }
  expandPreviewTimer = setTimeout(async () => {
    expandPreview.value = { total: 0, truncated: false, maxExpansion: 0, loading: true, error: '' };
    try {
      const r = await scanClient.previewExpandTargets({ targets: parsed });
      expandPreview.value = {
        total: r.total,
        truncated: r.truncated,
        maxExpansion: r.maxExpansion,
        loading: false,
        error: '',
      };
    } catch (e) {
      expandPreview.value = {
        total: 0,
        truncated: false,
        maxExpansion: 0,
        loading: false,
        error: errorMessage(e),
      };
    }
  }, 300);
}, { deep: false });

const canRun = computed(
  () =>
    !!runForm.value.projectId &&
    runTargetsParsed.value.length > 0 &&
    !(expandPreview.value?.truncated) &&
    !(expandPreview.value?.error),
);

async function runSuite() {
  if (submitting.value || !canRun.value) return;
  submitting.value = true;
  try {
    const r = await scanClient.runScanSuite({
      suiteId: runForm.value.suiteId,
      projectId: runForm.value.projectId,
      targets: runTargetsParsed.value,
    });
    toast.success(`套件 ${runForm.value.suiteName} 已运行 (run=${r.run?.id?.slice(0, 8) || '?'})`);
    showRun.value = false;
    if (r.run?.id) {
      router.push({ name: 'suite-run-detail', params: { id: r.run.id } });
    }
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

function kindLabel(k: string) {
  return ALL_KINDS.find((x) => x.value === k)?.label || k;
}
</script>

<template>
  <div class="page">
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h2>扫描套件</h2>
        <button class="primary" @click="showCreate = true">新建套件</button>
      </div>
      <p class="muted">
        套件 = N 个 kind 的扫描模板。运行时输入 targets，自动展开成 N 个 immediate task 并行执行。
      </p>

      <table v-if="suites.length > 0">
        <thead>
          <tr>
            <th>名称</th>
            <th>项目</th>
            <th>包含</th>
            <th>目标类型</th>
            <th>调度</th>
            <th>创建</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in suites" :key="s.id">
            <td>{{ s.name }}</td>
            <td class="muted">
              <span v-if="s.projectId">{{ projectName.get(s.projectId) || s.projectId.slice(0, 8) }}</span>
              <span v-else class="chip cross-chip" title="同租户跨项目可用">跨项目</span>
            </td>
            <td>
              <span v-for="k in s.kinds" :key="k" class="chip kind-chip">{{ kindLabel(k) }}</span>
            </td>
            <td>{{ s.targetKind }}</td>
            <td>
              <span v-if="s.scheduleKind === 'cron'" class="chip cron-chip" :title="`cron: ${s.cronExpr}`">
                ⏱ {{ s.cronExpr }}
              </span>
              <span v-else class="muted" style="font-size: 12px">手动</span>
            </td>
            <td class="muted" :title="formatAbsoluteTime(s.createdAt)">
              {{ formatRelativeTime(s.createdAt, nowTick) }}
            </td>
            <td>
              <div class="row" style="gap: 4px">
                <button class="primary" @click="openRun(s)">运行</button>
                <button class="danger" @click="delSuite(s)">删除</button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
      <p v-else class="muted" style="text-align: center; padding: 24px">
        暂无套件。新建一个模板（例：全栈套件 = port_scan + subdomain + fingerprint + vuln_scan）。
      </p>
    </div>

    <!-- 创建套件 modal -->
    <div v-if="showCreate" class="modal-mask">
      <div class="card modal">
        <h2>新建套件</h2>
        <div class="form">
          <div class="form-row">
            <span class="label">名称</span>
            <input v-model="newSuite.name" placeholder="如：全栈红队套件" :disabled="submitting" style="flex: 1" />
          </div>
          <div class="form-row">
            <span class="label">归属项目</span>
            <select v-model="newSuite.projectId" :disabled="submitting" style="flex: 1">
              <option value="">跨项目（同租户所有项目可用）</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="form-row form-row-top">
            <span class="label">包含 kind</span>
            <div style="flex: 1">
              <label v-for="k in ALL_KINDS" :key="k.value" class="kind-check">
                <input type="checkbox" :value="k.value" v-model="newSuite.kindsSelected" />
                {{ k.label }}
              </label>
            </div>
          </div>
          <div class="form-row">
            <span class="label">目标类型</span>
            <select v-model="newSuite.targetKind" :disabled="submitting" style="flex: 1">
              <option value="host">域名 (host)</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="url">URL</option>
            </select>
          </div>
          <div class="form-row">
            <span class="label">调度</span>
            <select v-model="newSuite.scheduleKind" :disabled="submitting" style="flex: 1">
              <option value="immediate">手动触发（默认）</option>
              <option value="cron">cron 周期触发</option>
            </select>
          </div>
          <div v-if="newSuite.scheduleKind === 'cron'" class="form-row">
            <span class="label">cron_expr</span>
            <input v-model="newSuite.cronExpr" placeholder="0 2 * * *（每天凌晨 2 点）"
                   :disabled="submitting" style="flex: 1; font-family: monospace" />
          </div>
          <div v-if="newSuite.scheduleKind === 'cron'" class="form-row form-row-top">
            <span class="label">默认目标</span>
            <div style="flex: 1">
              <textarea v-model="newSuite.defaultTargetsRaw"
                        placeholder="每行一个目标，逗号也可。cron 触发时用此列表。&#10;example.com&#10;10.0.0.0/24"
                        :disabled="submitting" rows="5"
                        style="width: 100%; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px" />
            </div>
          </div>
          <p v-if="newSuite.scheduleKind === 'cron' && !newSuite.projectId" class="muted"
             style="margin: 0; padding: 6px 8px; background: rgba(245, 158, 11, 0.12); border-radius: 4px; font-size: 12px">
            ⚠ cron 套件必须指定项目，跨项目暂不支持自动触发。
          </p>

          <div class="row">
            <button class="primary" :disabled="submitting" @click="createSuite">
              {{ submitting ? '创建中…' : '创建' }}
            </button>
            <button :disabled="submitting" @click="showCreate = false">取消</button>
          </div>
        </div>
      </div>
    </div>

    <!-- 运行套件 modal -->
    <div v-if="showRun" class="modal-mask">
      <div class="card modal">
        <h2>运行套件：{{ runForm.suiteName }}</h2>
        <div class="form">
          <div class="form-row">
            <span class="label">目标项目</span>
            <select v-model="runForm.projectId" :disabled="submitting" style="flex: 1">
              <option value="" disabled>选择项目</option>
              <option v-for="p in projects" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </div>
          <div class="form-row form-row-top">
            <span class="label">目标列表</span>
            <div style="flex: 1">
              <textarea
                v-model="runForm.targetsRaw"
                placeholder="一行一个目标，支持逗号分隔。&#10;example.com&#10;api.example.com"
                :disabled="submitting"
                rows="6"
                style="width: 100%; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 13px"
              />
              <div class="muted" style="font-size: 12px; margin-top: 4px">
                <span>{{ runTargetsParsed.length }} 项输入</span>
                <template v-if="expandPreview">
                  <span v-if="expandPreview.loading"> · 解析中…</span>
                  <template v-else-if="expandPreview.error">
                    <span class="expand-err"> · 解析失败：{{ expandPreview.error }}</span>
                  </template>
                  <template v-else>
                    <span v-if="expandPreview.total !== runTargetsParsed.length">
                      → <strong>{{ expandPreview.total }}</strong> 个目标（含 CIDR/范围展开）
                    </span>
                    <span v-if="expandPreview.truncated" class="expand-warn">
                      · 超出上限 {{ expandPreview.maxExpansion }}，请缩小输入
                    </span>
                  </template>
                </template>
              </div>
            </div>
          </div>

          <div class="row">
            <button class="primary" :disabled="submitting || !canRun" @click="runSuite">
              {{ submitting ? '触发中…' : '运行套件' }}
            </button>
            <button :disabled="submitting" @click="showRun = false">取消</button>
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
.chip {
  background: rgba(59, 130, 246, 0.08);
  color: #1d4ed8;
  border-radius: 4px;
  padding: 1px 8px;
  font-size: 12px;
  margin-right: 4px;
}
.cross-chip {
  background: rgba(245, 158, 11, 0.12);
  color: #b45309;
}
.kind-chip {
  margin-bottom: 2px;
  display: inline-block;
}
.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.36);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 100;
}
.modal {
  width: min(560px, calc(100vw - 32px));
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
.expand-err { color: #b91c1c; }
.expand-warn { color: #b45309; }
.cron-chip { background: rgba(124, 58, 237, 0.12); color: #6d28d9; font-family: ui-monospace, SFMono-Regular, monospace; }
</style>
