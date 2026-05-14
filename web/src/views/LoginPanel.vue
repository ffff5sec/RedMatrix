<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, nextTick, useTemplateRef } from 'vue';
import { identityClient } from '@/api/transport';
import { authStore } from '@/store/auth';
import { errorMessage } from '@/util/error';
import ChangeBootstrapPasswordModal from '@/components/ChangeBootstrapPasswordModal.vue';

const emit = defineEmits<{ (e: 'loggedIn'): void }>();

// 当前实例显示名：MVP 用 location.hostname 兜底；后续可由 server 公开 metadata 接口提供
const instanceName = (() => {
  try {
    return window.location.hostname || 'rm.local';
  } catch {
    return 'rm.local';
  }
})();

// 表单字段
const username = ref('admin');
const password = ref('');
const captchaAnswer = ref('');

// captcha 状态
type CaptchaState = 'loading' | 'ready' | 'error';
const captchaState = ref<CaptchaState>('loading');
const captchaID = ref('');
const captchaImg = ref(''); // data URL
const captchaErr = ref('');

// 提交状态
const submitting = ref(false);
const errMsg = ref('');

// 强制改密 Modal
const showChangeModal = ref(false);
const modalOldPassword = ref('');
const modalUsername = ref('');

// 改密成功后的 inline banner
const showSuccessBanner = ref(false);
let successTimer: number | undefined;

// refs
const passwordRef = useTemplateRef<HTMLInputElement>('passwordRef');

async function loadCaptcha() {
  captchaState.value = 'loading';
  captchaErr.value = '';
  try {
    const r = await identityClient.getCaptcha({});
    captchaID.value = r.captchaId;
    let bin = '';
    for (const b of r.imagePng) bin += String.fromCharCode(b);
    captchaImg.value = 'data:image/png;base64,' + btoa(bin);
    captchaAnswer.value = '';
    captchaState.value = 'ready';
  } catch (e) {
    captchaErr.value = errorMessage(e);
    captchaState.value = 'error';
  }
}

const canSubmit = computed(
  () =>
    !submitting.value &&
    captchaState.value === 'ready' &&
    username.value.length > 0 &&
    password.value.length > 0 &&
    captchaAnswer.value.length > 0,
);

async function submit() {
  if (!canSubmit.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    const res = await identityClient.login({
      username: username.value,
      password: password.value,
      captchaId: captchaID.value,
      captchaAnswer: captchaAnswer.value,
    });
    if (!res.user) {
      errMsg.value = '后端未返回 user';
      await loadCaptcha();
      // refocus password
      await nextTick();
      passwordRef.value?.focus();
      return;
    }

    // 必须先 set，让后续 ChangePassword 调用能拿到 Authorization 头
    authStore.set({
      token: res.accessToken,
      username: res.user.username,
      role: res.user.role,
      userId: res.user.id,
      expiresAt: res.expiresAt?.toDate().toISOString(),
    });

    if (res.mustChangePassword) {
      modalOldPassword.value = password.value;
      modalUsername.value = res.user.username;
      showChangeModal.value = true;
      return;
    }

    emit('loggedIn');
  } catch (e) {
    errMsg.value = errorMessage(e);
    // 验证码已被消费
    await loadCaptcha();
    await nextTick();
    passwordRef.value?.focus();
  } finally {
    submitting.value = false;
  }
}

function onPasswordChanged() {
  // 改密成功：清 token，跳回登录态，提示用户用新密码重登
  showChangeModal.value = false;
  authStore.clear();
  password.value = '';
  captchaAnswer.value = '';
  errMsg.value = '';
  loadCaptcha();
  showSuccessBanner.value = true;
  if (successTimer) window.clearTimeout(successTimer);
  successTimer = window.setTimeout(() => {
    showSuccessBanner.value = false;
  }, 5000);
  // focus password 让用户立即用新密码登录
  nextTick(() => passwordRef.value?.focus());
}

onMounted(() => {
  loadCaptcha();
  // dev-mode 视觉调试钩子：?debug=modal|error|success|enabled|submitting
  if (import.meta.env.DEV) {
    const q = new URLSearchParams(location.search).get('debug');
    if (q === 'modal') {
      modalUsername.value = 'admin';
      modalOldPassword.value = 'bootstrap-temp-password';
      showChangeModal.value = true;
    } else if (q === 'error') {
      errMsg.value = '[connect:invalid_argument] AUTH_FAILED: 用户名或密码错误';
    } else if (q === 'success') {
      showSuccessBanner.value = true;
    } else if (q === 'enabled' || q === 'submitting') {
      // 模拟 captcha 已就绪（占位 1×1 PNG）+ 三字段填齐
      captchaID.value = 'dev-captcha';
      captchaImg.value =
        'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
      captchaState.value = 'ready';
      password.value = 'demo-password';
      captchaAnswer.value = 'K3M9F';
      if (q === 'submitting') submitting.value = true;
    }
  }
});
onUnmounted(() => {
  if (successTimer) window.clearTimeout(successTimer);
});
</script>

<template>
  <section class="login-page" aria-label="登录">
    <!-- 左侧：实例 + 产品自陈述 -->
    <aside class="login-ctx" aria-label="实例与产品信息">
      <header class="login-brand">
        <svg
          class="login-logo"
          viewBox="0 0 24 24"
          fill="none"
          aria-hidden="true"
        >
          <rect
            x="3"
            y="3"
            width="7"
            height="7"
            stroke="currentColor"
            stroke-width="1.5"
          />
          <rect
            x="14"
            y="3"
            width="7"
            height="7"
            stroke="currentColor"
            stroke-width="1.5"
          />
          <rect
            x="3"
            y="14"
            width="7"
            height="7"
            stroke="currentColor"
            stroke-width="1.5"
          />
          <rect
            x="14"
            y="14"
            width="7"
            height="7"
            fill="currentColor"
            stroke="none"
          />
        </svg>
        <div class="login-brand-text">
          <div class="login-brand-name">RedMatrix</div>
          <div class="login-brand-tag">v0.1.0-rc · Identity 演示</div>
        </div>
      </header>

      <section class="login-statement">
        <div class="login-statement-eyebrow">
          RED-TEAM OPERATIONS PLATFORM
        </div>
        <h2 class="login-statement-big">
          从攻击面到权限维持，<br />一处串起红队全链路。
        </h2>
        <p class="login-statement-sub">
          ASM、漏洞、利用、后渗透、钓鱼。统一资产、统一插件、统一审计。
          自部署，数据不出网。
        </p>
      </section>

      <dl class="login-meta" aria-label="实例运行状态">
        <div class="login-meta-row">
          <dt class="login-meta-key">Instance</dt>
          <dd class="login-meta-val">{{ instanceName }}</dd>
          <dd class="login-meta-aux">tls 1.3</dd>
        </div>
        <div class="login-meta-row">
          <dt class="login-meta-key">Auth</dt>
          <dd class="login-meta-val">password + captcha</dd>
          <dd class="login-meta-aux">JWT</dd>
        </div>
        <div class="login-meta-row">
          <dt class="login-meta-key">Build</dt>
          <dd class="login-meta-val">a1b2c3d</dd>
          <dd class="login-meta-aux">2026-04-22</dd>
        </div>
      </dl>
    </aside>

    <!-- 右侧：登录表单 -->
    <main class="login-auth" aria-label="登录表单">
      <div class="login-auth-inner">
        <div class="login-auth-eyebrow">登录到实例</div>
        <h1 class="login-auth-title">{{ instanceName }}</h1>
        <p class="login-auth-sub">
          凭证仅在本实例校验。RedMatrix 不向外网发起验证请求。
        </p>

        <!-- 改密成功 banner -->
        <div
          v-if="showSuccessBanner"
          class="login-banner login-banner--success"
          role="status"
        >
          <svg
            class="login-banner-icon"
            viewBox="0 0 16 16"
            fill="none"
            aria-hidden="true"
          >
            <circle
              cx="8"
              cy="8"
              r="7"
              stroke="currentColor"
              stroke-width="1.5"
            />
            <path
              d="M5 8.5l2 2 4-4"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
          <span>密码已更新，请用新密码重新登录。</span>
        </div>

        <form @submit.prevent="submit">
          <div class="login-field">
            <label class="login-field-label" for="username">用户名</label>
            <input
              id="username"
              v-model="username"
              class="login-input login-input--mono"
              type="text"
              autocomplete="username"
              :disabled="submitting"
            />
          </div>

          <div class="login-field">
            <label class="login-field-label" for="password">密码</label>
            <input
              id="password"
              ref="passwordRef"
              v-model="password"
              class="login-input"
              type="password"
              autocomplete="current-password"
              :disabled="submitting"
              @keyup.enter="submit"
            />
          </div>

          <div class="login-field">
            <label class="login-field-label" for="captcha">验证码</label>
            <div class="login-captcha">
              <input
                id="captcha"
                v-model="captchaAnswer"
                class="login-input login-input--mono login-captcha-input"
                type="text"
                inputmode="text"
                maxlength="6"
                autocomplete="off"
                :disabled="submitting || captchaState !== 'ready'"
                @keyup.enter="submit"
              />

              <button
                v-if="captchaState === 'ready'"
                type="button"
                class="login-captcha-img"
                :title="`图形验证码（点击刷新）`"
                aria-label="图形验证码，点击或按回车刷新"
                @click="loadCaptcha"
              >
                <img :src="captchaImg" alt="" />
              </button>

              <div
                v-else-if="captchaState === 'loading'"
                class="login-captcha-skeleton"
                role="status"
                aria-label="验证码加载中"
              >
                加载中
              </div>

              <button
                v-else
                type="button"
                class="login-captcha-retry"
                aria-label="验证码加载失败，点击重试"
                :title="captchaErr"
                @click="loadCaptcha"
              >
                重试
              </button>
            </div>
          </div>

          <div v-if="errMsg" class="login-banner login-banner--error" role="alert">
            <svg
              class="login-banner-icon"
              viewBox="0 0 16 16"
              fill="none"
              aria-hidden="true"
            >
              <circle
                cx="8"
                cy="8"
                r="7"
                stroke="currentColor"
                stroke-width="1.5"
              />
              <path
                d="M8 4v5"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
              />
              <circle cx="8" cy="11.5" r="0.75" fill="currentColor" />
            </svg>
            <span>{{ errMsg }}</span>
          </div>

          <button
            type="submit"
            class="login-submit"
            :disabled="!canSubmit"
          >
            {{ submitting ? '登录中…' : '登录' }}
          </button>
        </form>

        <p class="login-foot">
          首次启动？使用
          <code class="login-foot-code">ADMIN_BOOTSTRAP_PASSWORD</code>
          或服务进程 stdout 输出的随机密码登录 admin。
          <br />
          忘记密码？请联系当前实例的 SuperAdmin。
        </p>
      </div>
    </main>

    <ChangeBootstrapPasswordModal
      v-if="showChangeModal"
      :current-password="modalOldPassword"
      :username="modalUsername"
      @changed="onPasswordChanged"
    />
  </section>
</template>

<style scoped>
.login-page {
  display: flex;
  min-height: 100vh;
  font-family: var(--rm-font-sans);
  color: var(--rm-color-text-primary);
  background: var(--rm-color-surface-base);
  font-size: 14px;
  line-height: 1.4;
}

/* === 左侧：context === */
.login-ctx {
  flex: 1 1 56%;
  background: var(--rm-color-surface-context);
  border-right: 1px solid var(--rm-color-hairline);
  padding: var(--rm-space-7) var(--rm-space-8);
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-7);
  min-height: 100vh;
  position: relative;
  overflow: hidden;
}

/* ambient 装饰刻意省略：左侧 surface 保持纯净，让 brand row + 自陈述 + meta 三段
   组成的信息层级独立成立。"专业感 > 装饰性"原则的物理实现。 */

.login-brand {
  display: flex;
  align-items: center;
  gap: var(--rm-space-4);
}
.login-logo {
  width: 56px;
  height: 56px;
  flex-shrink: 0;
  color: var(--rm-color-primary);
}
.login-brand-text {
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-1);
}
.login-brand-name {
  font-size: 22px;
  font-weight: 600;
  letter-spacing: 0.01em;
  line-height: 1;
  color: var(--rm-color-text-primary);
}
.login-brand-tag {
  font-family: var(--rm-font-mono);
  font-size: 12px;
  color: var(--rm-color-text-tertiary);
  letter-spacing: 0.04em;
}

.login-statement {
  max-width: 28em;
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-3);
}
.login-statement-eyebrow {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  color: var(--rm-color-text-tertiary);
  margin-bottom: var(--rm-space-1);
}
.login-statement-big {
  font-size: 28px;
  font-weight: 600;
  line-height: 1.25;
  color: var(--rm-color-text-primary);
  letter-spacing: -0.005em;
  margin: 0;
}
.login-statement-sub {
  font-size: 14px;
  line-height: 1.6;
  color: var(--rm-color-text-secondary);
  margin: 0;
}

.login-meta {
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-3);
  margin: auto 0 0;
  padding-top: var(--rm-space-6);
  border-top: 1px solid var(--rm-color-hairline);
  font-family: var(--rm-font-mono);
  font-size: 13px;
}
.login-meta-row {
  display: grid;
  grid-template-columns: 96px 1fr auto;
  align-items: baseline;
  gap: var(--rm-space-4);
  margin: 0;
}
.login-meta-key {
  color: var(--rm-color-text-tertiary);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin: 0;
}
.login-meta-val {
  color: var(--rm-color-text-primary);
  font-weight: 500;
  margin: 0;
}
.login-meta-aux {
  color: var(--rm-color-text-tertiary);
  font-size: 12px;
  margin: 0;
}

/* === 右侧：auth === */
.login-auth {
  flex: 0 0 44%;
  background: var(--rm-color-surface-canvas);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--rm-space-7) var(--rm-space-8);
  min-height: 100vh;
}
.login-auth-inner {
  width: 100%;
  max-width: 360px;
}
.login-auth-eyebrow {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--rm-color-text-tertiary);
  margin-bottom: var(--rm-space-3);
}
.login-auth-title {
  font-size: 22px;
  font-weight: 600;
  margin: 0 0 var(--rm-space-2);
  color: var(--rm-color-text-primary);
  line-height: 1.3;
  font-family: var(--rm-font-mono);
  letter-spacing: 0.005em;
}
.login-auth-sub {
  font-size: 13px;
  color: var(--rm-color-text-secondary);
  margin: 0 0 var(--rm-space-6);
  line-height: 1.5;
}

.login-field {
  margin-bottom: var(--rm-space-4);
}
.login-field-label {
  display: block;
  font-size: 12px;
  font-weight: 500;
  color: var(--rm-color-text-secondary);
  margin-bottom: var(--rm-space-2);
}
.login-input {
  width: 100%;
  height: 36px;
  padding: 0 var(--rm-space-3);
  font-size: 14px;
  font-family: var(--rm-font-sans);
  color: var(--rm-color-text-primary);
  background: var(--rm-color-surface-canvas);
  border: 1px solid var(--rm-color-border);
  border-radius: var(--rm-radius-md);
  outline: none;
  transition: border-color var(--rm-duration-instant) var(--rm-ease-out),
    box-shadow var(--rm-duration-instant) var(--rm-ease-out);
}
.login-input--mono {
  font-family: var(--rm-font-mono);
}
.login-input:hover {
  border-color: #4096ff;
}
.login-input:focus {
  border-color: var(--rm-color-primary);
  box-shadow: 0 0 0 4px var(--rm-color-primary-soft);
}
.login-input:disabled {
  background: var(--rm-color-auditor-surface);
  color: var(--rm-color-text-disabled);
  cursor: not-allowed;
}

.login-captcha {
  display: flex;
  gap: var(--rm-space-2);
  align-items: stretch;
}
.login-captcha-input {
  flex: 1 1 auto;
  min-width: 0;
}
.login-captcha-img,
.login-captcha-skeleton,
.login-captcha-retry {
  width: 96px;
  height: 36px;
  flex-shrink: 0;
  border: 1px solid var(--rm-color-border);
  border-radius: var(--rm-radius-md);
  padding: 0;
  background: var(--rm-color-surface-canvas);
  font-family: var(--rm-font-mono);
  font-size: 12px;
  color: var(--rm-color-text-tertiary);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  overflow: hidden;
  transition: border-color var(--rm-duration-instant) var(--rm-ease-out);
}
.login-captcha-img {
  cursor: pointer;
  background: var(--rm-color-surface-canvas);
}
.login-captcha-img img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}
.login-captcha-img:hover,
.login-captcha-retry:hover {
  border-color: var(--rm-color-primary);
}
.login-captcha-img:focus-visible,
.login-captcha-retry:focus-visible {
  outline: 2px solid var(--rm-color-primary);
  outline-offset: 2px;
}
.login-captcha-skeleton {
  background: var(--rm-color-auditor-surface);
  cursor: default;
  color: var(--rm-color-text-tertiary);
}
.login-captcha-retry {
  color: var(--rm-color-error-deep);
  background: var(--rm-color-error-soft);
  border-color: var(--rm-color-error-border);
  font-family: var(--rm-font-sans);
  font-weight: 500;
}

.login-banner {
  display: flex;
  gap: var(--rm-space-2);
  align-items: flex-start;
  padding: var(--rm-space-3);
  border-radius: var(--rm-radius-sm);
  font-size: 13px;
  line-height: 1.5;
  margin-bottom: var(--rm-space-3);
}
.login-banner-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
  margin-top: 2px;
}
.login-banner--error {
  background: var(--rm-color-error-soft);
  border: 1px solid var(--rm-color-error-border);
  color: var(--rm-color-error-deep);
}
.login-banner--success {
  background: var(--rm-color-success-soft);
  border: 1px solid var(--rm-color-success-border);
  color: var(--rm-color-success-deep);
  margin-bottom: var(--rm-space-5);
}

.login-submit {
  width: 100%;
  height: 36px;
  margin-top: var(--rm-space-2);
  background: var(--rm-color-primary);
  color: #ffffff;
  border: none;
  border-radius: var(--rm-radius-sm);
  font-family: var(--rm-font-sans);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: background var(--rm-duration-instant) var(--rm-ease-out);
}
.login-submit:hover:not(:disabled) {
  background: var(--rm-color-primary-deep);
}
.login-submit:active:not(:disabled) {
  background: #003eb3;
}
.login-submit:focus-visible {
  outline: 2px solid var(--rm-color-primary);
  outline-offset: 2px;
}
.login-submit:disabled {
  background: var(--rm-color-auditor-surface);
  color: var(--rm-color-text-disabled);
  border: 1px solid var(--rm-color-hairline);
  cursor: not-allowed;
}

.login-foot {
  margin-top: var(--rm-space-5);
  font-size: 12px;
  color: var(--rm-color-text-tertiary);
  line-height: 1.6;
}
.login-foot-code {
  font-family: var(--rm-font-mono);
  font-size: 12px;
  color: var(--rm-color-text-secondary);
  padding: 1px 4px;
  background: var(--rm-color-auditor-surface);
  border-radius: 3px;
}

/* === 响应式：< 960px 折叠为单列 === */
@media (max-width: 960px) {
  .login-page {
    flex-direction: column;
  }
  .login-ctx {
    flex: 0 0 auto;
    padding: var(--rm-space-5) var(--rm-space-5);
    gap: var(--rm-space-4);
    min-height: 0;
    border-right: none;
    border-bottom: 1px solid var(--rm-color-hairline);
  }
  /* 移动端折叠也不需要单独处理水印（已删） */
  .login-statement {
    display: none; /* 移动视口下省略大字陈述，保留 brand + meta */
  }
  .login-meta {
    margin-top: 0;
    padding-top: var(--rm-space-4);
  }
  .login-auth {
    flex: 1 1 auto;
    padding: var(--rm-space-6) var(--rm-space-5);
    min-height: 0;
  }
}

@media (max-width: 480px) {
  .login-ctx {
    padding: var(--rm-space-4) var(--rm-space-4);
  }
  .login-meta-row {
    grid-template-columns: 80px 1fr;
  }
  .login-meta-aux {
    display: none;
  }
  .login-auth {
    padding: var(--rm-space-5) var(--rm-space-4);
  }
}
</style>
