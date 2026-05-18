<script setup lang="ts">
// FingerprintsPanel —— 指纹规则管理（PR-S74，SPEC §2.5）。
//
// 内嵌规则 read-only 一览；自定义规则按租户隔离，SA + PA 可 CRUD。
import { ref, computed, onMounted } from 'vue';

import { fingerprintClient } from '@/api/transport';
import { useToast } from '@/composables/useToast';
import { errorMessage } from '@/util/error';
import { authStore } from '@/store/auth';
import type { Rule } from '@/gen/proto/redmatrix/fingerprint/v1/fingerprint_pb';

const toast = useToast();

const builtin = ref<Rule[]>([]);
const custom = ref<Rule[]>([]);
const loading = ref(false);
const showCreate = ref(false);
// PR-S77 批量导入
const showImport = ref(false);
const importYAML = ref('');
const importPolicy = ref<'skip' | 'overwrite'>('skip');
const importSubmitting = ref(false);
const importResult = ref<{
  created: number;
  skipped: number;
  failed: number;
  details: { name: string; status: string; error: string }[];
} | null>(null);
const submitting = ref(false);

const form = ref({
  name: '',
  keyword: '',
  fields: '',  // 逗号分隔字符串；提交时拆 array
  caseSensitive: false,
  enabled: true,
  description: '',
});

const canWrite = computed(() => authStore.isSuperAdmin() || authStore.isProjectAdmin());

async function refresh() {
  loading.value = true;
  try {
    const [b, c] = await Promise.all([
      fingerprintClient.listBuiltinRules({}),
      fingerprintClient.listCustomRules({}),
    ]);
    builtin.value = b.rules;
    custom.value = c.rules;
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    loading.value = false;
  }
}

onMounted(refresh);

function resetForm() {
  form.value = {
    name: '',
    keyword: '',
    fields: '',
    caseSensitive: false,
    enabled: true,
    description: '',
  };
}

async function submit() {
  if (submitting.value) return;
  if (!form.value.name.trim() || !form.value.keyword.trim()) {
    toast.error('名称和关键字必填');
    return;
  }
  submitting.value = true;
  try {
    const fields = form.value.fields
      .split(',')
      .map(s => s.trim())
      .filter(Boolean);
    await fingerprintClient.createCustomRule({
      name: form.value.name,
      keyword: form.value.keyword,
      fields,
      caseSensitive: form.value.caseSensitive,
      enabled: form.value.enabled,
      description: form.value.description,
    });
    toast.success(`规则 ${form.value.name} 已创建`);
    showCreate.value = false;
    resetForm();
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    submitting.value = false;
  }
}

async function toggleEnabled(r: Rule) {
  try {
    await fingerprintClient.toggleCustomRule({ id: r.id, enabled: !r.enabled });
    toast.success(`规则 ${r.name} 已${!r.enabled ? '启用' : '停用'}`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}

async function bulkImport() {
  if (importSubmitting.value || !importYAML.value.trim()) return;
  importSubmitting.value = true;
  importResult.value = null;
  try {
    const r = await fingerprintClient.bulkImportCustomRules({
      yamlText: importYAML.value,
      duplicatePolicy: importPolicy.value,
    });
    importResult.value = {
      created: r.created,
      skipped: r.skipped,
      failed: r.failed,
      details: r.details.map(d => ({ name: d.name, status: d.status, error: d.error })),
    };
    if (r.failed === 0) {
      toast.success(`导入完成：新建 ${r.created} / 跳过 ${r.skipped}`);
    } else {
      toast.warning(`导入完成：新建 ${r.created} / 跳过 ${r.skipped} / 失败 ${r.failed}`);
    }
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  } finally {
    importSubmitting.value = false;
  }
}

function resetImport() {
  importYAML.value = '';
  importResult.value = null;
  importPolicy.value = 'skip';
}

async function del(r: Rule) {
  if (!confirm(`删除自定义规则 ${r.name}？已删除不可恢复（可同名重建）。`)) return;
  try {
    await fingerprintClient.deleteCustomRule({ id: r.id });
    toast.warning(`规则 ${r.name} 已删除`);
    await refresh();
  } catch (e) {
    toast.error(errorMessage(e));
  }
}
</script>

<template>
  <div class="page">
    <div class="header">
      <h2 style="margin: 0">指纹规则库</h2>
      <span class="muted">
        匹配资产 fingerprint 结果字段（webserver / title / body / tech 等）→ 命中即写入 tech 标签。
      </span>
    </div>

    <!-- 内嵌规则 -->
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h3 style="margin: 0">内嵌规则<span class="muted" style="margin-left: 8px">{{ builtin.length }} 条</span></h3>
        <button @click="refresh" :disabled="loading">{{ loading ? '加载中…' : '刷新' }}</button>
      </div>
      <p class="muted">RedMatrix 自带，由 rules.yaml 内嵌，不可改；通过升级二进制更新。</p>
      <table>
        <thead>
          <tr>
            <th style="width: 200px">名称</th>
            <th style="width: 160px">字段</th>
            <th>关键字</th>
            <th style="width: 60px">CS</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in builtin" :key="r.name">
            <td>{{ r.name }}</td>
            <td class="muted">{{ r.fields.join(', ') || '(全字段)' }}</td>
            <td><code class="mono">{{ r.keyword }}</code></td>
            <td>{{ r.caseSensitive ? '✓' : '' }}</td>
          </tr>
          <tr v-if="builtin.length === 0 && !loading">
            <td colspan="4" class="muted" style="text-align: center; padding: 16px">暂无内嵌规则。</td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 自定义规则 -->
    <div class="card">
      <div class="row" style="justify-content: space-between; align-items: baseline">
        <h3 style="margin: 0">自定义规则<span class="muted" style="margin-left: 8px">{{ custom.length }} 条</span></h3>
        <div v-if="canWrite" class="row" style="gap: 8px">
          <button @click="showImport = true; resetImport()">批量导入</button>
          <button class="primary" @click="showCreate = true">新建规则</button>
        </div>
      </div>
      <p class="muted">仅本租户可见可改；变更后 ≤ 60s 在扫描端生效。</p>

      <table>
        <thead>
          <tr>
            <th style="width: 200px">名称</th>
            <th style="width: 160px">字段</th>
            <th>关键字</th>
            <th style="width: 60px">CS</th>
            <th style="width: 70px">启用</th>
            <th style="width: 180px">备注</th>
            <th style="width: 110px" v-if="canWrite">操作</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in custom" :key="r.id">
            <td>{{ r.name }}</td>
            <td class="muted">{{ r.fields.join(', ') || '(全字段)' }}</td>
            <td><code class="mono">{{ r.keyword }}</code></td>
            <td>{{ r.caseSensitive ? '✓' : '' }}</td>
            <td>
              <span :class="['chip', r.enabled ? 'green' : 'gray']">{{ r.enabled ? 'on' : 'off' }}</span>
            </td>
            <td class="muted">{{ r.description || '—' }}</td>
            <td v-if="canWrite">
              <button class="link-btn" @click="toggleEnabled(r)">{{ r.enabled ? '停用' : '启用' }}</button>
              <button class="link-btn red" style="margin-left: 6px" @click="del(r)">删除</button>
            </td>
          </tr>
          <tr v-if="custom.length === 0 && !loading">
            <td :colspan="canWrite ? 7 : 6" class="muted" style="text-align: center; padding: 16px">
              暂无自定义规则。<a v-if="canWrite" href="#" @click.prevent="showCreate = true">新建</a>。
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- 新建 -->
    <div v-if="showCreate" class="overlay">
      <div class="modal">
        <h3 style="margin-top: 0">新建自定义规则</h3>
        <div class="form-row"><span class="label">名称</span>
          <input v-model="form.name" placeholder="WordPress / 致远OA / 我的中台 ..." :disabled="submitting" /></div>
        <div class="form-row"><span class="label">关键字</span>
          <input v-model="form.keyword" placeholder="子串，如 wp-content 或 /seeyon/" :disabled="submitting" /></div>
        <div class="form-row"><span class="label">字段</span>
          <input v-model="form.fields" placeholder="逗号分隔（body, title, webserver；留空 = 全部）" :disabled="submitting" /></div>
        <div class="form-row"><span class="label">大小写敏感</span>
          <label><input type="checkbox" v-model="form.caseSensitive" :disabled="submitting" /> 区分大小写</label></div>
        <div class="form-row"><span class="label">启用</span>
          <label><input type="checkbox" v-model="form.enabled" :disabled="submitting" /> 立即生效</label></div>
        <div class="form-row form-row-top"><span class="label">备注</span>
          <textarea v-model="form.description" rows="2" :disabled="submitting" style="flex: 1" placeholder="可选；管理员留档" /></div>
        <div class="row" style="justify-content: flex-end; gap: 8px; margin-top: 8px">
          <button @click="showCreate = false; resetForm()" :disabled="submitting">取消</button>
          <button class="primary" :disabled="submitting" @click="submit">{{ submitting ? '保存中…' : '保存' }}</button>
        </div>
      </div>
    </div>

    <!-- PR-S77 批量导入 -->
    <div v-if="showImport" class="overlay">
      <div class="modal" style="width: 760px">
        <h3 style="margin-top: 0">批量导入指纹规则</h3>
        <p class="muted" style="margin-top: 0">
          粘贴 RedMatrix YAML（同 rules.yaml schema：`rules:` 数组 + name / fields / keyword / case_sensitive 字段）。
          常见开源源（EHole / FingerprintHub / Wappalyzer）可写小脚本转 YAML。
        </p>
        <div class="form-row form-row-top">
          <span class="label">YAML 内容</span>
          <textarea v-model="importYAML" rows="14" :disabled="importSubmitting"
            style="flex: 1; font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px"
            :placeholder="'rules:\n  - name: MyTech\n    fields: [body, title]\n    keyword: mytech-banner\n    case_sensitive: false'" />
        </div>
        <div class="form-row">
          <span class="label">同名策略</span>
          <label style="margin-right: 12px">
            <input type="radio" value="skip" v-model="importPolicy" :disabled="importSubmitting" /> 跳过同名
          </label>
          <label>
            <input type="radio" value="overwrite" v-model="importPolicy" :disabled="importSubmitting" /> 覆盖（先软删旧再插）
          </label>
        </div>
        <div v-if="importResult" class="info" style="margin-top: 8px">
          <strong>导入结果</strong>：
          新建 <b style="color: #15803d">{{ importResult.created }}</b> /
          跳过 <span class="muted">{{ importResult.skipped }}</span> /
          失败 <b v-if="importResult.failed > 0" style="color: #dc2626">{{ importResult.failed }}</b><span v-else>0</span>
          <details v-if="importResult.failed > 0" style="margin-top: 4px">
            <summary>查看失败详情</summary>
            <ul style="font-size: 12px; margin: 4px 0 0 0">
              <li v-for="d in importResult.details.filter(x => x.status === 'failed')" :key="d.name">
                <code>{{ d.name }}</code>：{{ d.error }}
              </li>
            </ul>
          </details>
        </div>
        <div class="row" style="justify-content: flex-end; gap: 8px; margin-top: 12px">
          <button @click="showImport = false; resetImport()" :disabled="importSubmitting">关闭</button>
          <button class="primary" :disabled="importSubmitting || !importYAML.trim()" @click="bulkImport">
            {{ importSubmitting ? '导入中…' : '开始导入' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.page { display: flex; flex-direction: column; gap: 16px; }
.header { display: flex; align-items: baseline; gap: 12px; flex-wrap: wrap; }
.card {
  background: var(--surface, #fff);
  border: 1px solid var(--border, #e2e8f0);
  border-radius: 8px;
  padding: 16px;
}
.muted { color: var(--muted, #6b7280); }
.mono { font-family: ui-monospace, SFMono-Regular, monospace; font-size: 12px; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
.chip.green { background: rgba(34,197,94,0.16); color: #15803d; }
.chip.gray  { background: rgba(0,0,0,0.06);    color: #6b7280; }
.link-btn { background: transparent; border: none; color: var(--accent, #2563eb); cursor: pointer; padding: 0; font-size: 13px; }
.link-btn.red { color: #dc2626; }
.link-btn:hover { text-decoration: underline; }

.overlay {
  position: fixed; inset: 0; background: rgba(0,0,0,0.4);
  display: flex; align-items: center; justify-content: center; z-index: 50;
}
.modal {
  background: #fff; border-radius: 8px; padding: 20px;
  width: 560px; max-width: 92vw;
  box-shadow: 0 12px 32px rgba(0,0,0,0.18);
}
.form-row { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; }
.form-row-top { align-items: flex-start; }
.label { width: 110px; color: var(--muted, #6b7280); font-size: 13px; }
.form-row input, .form-row textarea, .form-row select { flex: 1; }
</style>
