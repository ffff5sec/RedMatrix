<script setup lang="ts">
import { ref, computed, onMounted, nextTick, useTemplateRef } from 'vue';
import { identityClient } from '@/api/transport';
import { errorMessage } from '@/util/error';

interface Props {
  /** 当前登录用户刚输入的旧密码（bootstrap）。Modal 内部用它做 ChangePassword.current_password */
  currentPassword: string;
  /** 用户名，仅作展示，非实际接口需要 */
  username: string;
}
const props = defineProps<Props>();
const emit = defineEmits<{
  /** 改密成功，父组件应清 token + 重置登录表单 */
  (e: 'changed'): void;
}>();

const newPassword = ref('');
const confirmPassword = ref('');
const submitting = ref(false);
const errMsg = ref('');

const newPasswordRef = useTemplateRef<HTMLInputElement>('newPasswordRef');
const confirmRef = useTemplateRef<HTMLInputElement>('confirmRef');
const submitRef = useTemplateRef<HTMLButtonElement>('submitRef');

// 强度评估：长度 + 字符类多样性
type Strength = { level: 0 | 1 | 2 | 3; label: string };
const strength = computed<Strength>(() => {
  const v = newPassword.value;
  if (!v) return { level: 0, label: '' };
  let classes = 0;
  if (/[a-z]/.test(v)) classes++;
  if (/[A-Z]/.test(v)) classes++;
  if (/[0-9]/.test(v)) classes++;
  if (/[^a-zA-Z0-9]/.test(v)) classes++;

  if (v.length < 8) return { level: 1, label: '弱' };
  if (v.length < 12 || classes < 3) return { level: 2, label: '中' };
  return { level: 3, label: '强' };
});

const mismatch = computed(
  () => confirmPassword.value !== '' && confirmPassword.value !== newPassword.value,
);

const canSubmit = computed(
  () =>
    !submitting.value &&
    // PR-S38: 与后端 auth.service 强一致（最低 12）；原 8 提交后会被后端 422 拒绝
    newPassword.value.length >= 12 &&
    newPassword.value === confirmPassword.value,
);

async function submit() {
  if (!canSubmit.value) return;
  submitting.value = true;
  errMsg.value = '';
  try {
    await identityClient.changePassword({
      currentPassword: props.currentPassword,
      newPassword: newPassword.value,
    });
    emit('changed');
  } catch (e) {
    errMsg.value = errorMessage(e);
  } finally {
    submitting.value = false;
  }
}

// 焦点陷阱：Tab 在最后一个 focusable 后跳回第一个
function onKeydown(e: KeyboardEvent) {
  // ESC 不允许关闭：bootstrap 改密是强制流程
  if (e.key === 'Escape') {
    e.preventDefault();
    return;
  }
  if (e.key !== 'Tab') return;

  const els = [newPasswordRef.value, confirmRef.value, submitRef.value].filter(
    (el): el is HTMLInputElement | HTMLButtonElement =>
      el !== null && !el.disabled,
  );
  if (els.length === 0) return;

  const first = els[0]!;
  const last = els[els.length - 1]!;
  const active = document.activeElement as HTMLElement | null;

  if (e.shiftKey && active === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && active === last) {
    e.preventDefault();
    first.focus();
  }
}

onMounted(async () => {
  await nextTick();
  newPasswordRef.value?.focus();
});
</script>

<template>
  <div
    class="rm-modal-backdrop"
    role="dialog"
    aria-modal="true"
    aria-labelledby="bp-modal-title"
    aria-describedby="bp-modal-desc"
    @keydown="onKeydown"
  >
    <div class="rm-modal" tabindex="-1">
      <div class="rm-modal-header">
        <svg
          class="rm-modal-icon"
          viewBox="0 0 24 24"
          fill="none"
          aria-hidden="true"
        >
          <path
            d="M12 8v5"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
          />
          <circle cx="12" cy="16" r="1" fill="currentColor" />
          <circle
            cx="12"
            cy="12"
            r="9"
            stroke="currentColor"
            stroke-width="1.5"
            fill="none"
          />
        </svg>
        <div>
          <h2 id="bp-modal-title" class="rm-modal-title">
            首次登录：请设置新密码
          </h2>
          <p id="bp-modal-desc" class="rm-modal-desc">
            为安全起见，bootstrap 密码必须更换。新密码生效后，请用新密码重新登录。
          </p>
        </div>
      </div>

      <form class="rm-modal-form" @submit.prevent="submit">
        <div class="rm-field">
          <label class="rm-field-label" for="bp-new-password">
            新密码
            <span class="rm-field-hint">至少 12 个字符</span>
          </label>
          <input
            id="bp-new-password"
            ref="newPasswordRef"
            v-model="newPassword"
            class="rm-input"
            type="password"
            autocomplete="new-password"
            :disabled="submitting"
          />
          <div
            v-if="newPassword"
            class="rm-strength"
            :class="`rm-strength--${strength.level}`"
            aria-live="polite"
          >
            <div class="rm-strength-track">
              <span class="rm-strength-bar"></span>
              <span class="rm-strength-bar"></span>
              <span class="rm-strength-bar"></span>
            </div>
            <span class="rm-strength-label">{{ strength.label }}</span>
          </div>
        </div>

        <div class="rm-field">
          <label class="rm-field-label" for="bp-confirm-password">
            确认新密码
          </label>
          <input
            id="bp-confirm-password"
            ref="confirmRef"
            v-model="confirmPassword"
            class="rm-input"
            :class="{ 'rm-input--error': mismatch }"
            type="password"
            autocomplete="new-password"
            :disabled="submitting"
            @keyup.enter="submit"
          />
          <p v-if="mismatch" class="rm-field-error">两次输入不一致。</p>
        </div>

        <div v-if="errMsg" class="rm-banner rm-banner--error" role="alert">
          <svg
            class="rm-banner-icon"
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
            <path d="M8 4v5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
            <circle cx="8" cy="11.5" r="0.75" fill="currentColor" />
          </svg>
          <span>{{ errMsg }}</span>
        </div>

        <button
          ref="submitRef"
          type="submit"
          class="rm-btn rm-btn--primary rm-modal-submit"
          :disabled="!canSubmit"
        >
          {{ submitting ? '保存中…' : '设置新密码' }}
        </button>
      </form>

      <p class="rm-modal-foot">
        当前账号：<span class="rm-mono">{{ username }}</span>
      </p>
    </div>
  </div>
</template>

<style scoped>
.rm-modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: var(--rm-space-4);
  font-family: var(--rm-font-sans);
}

.rm-modal {
  background: var(--rm-color-surface-canvas);
  border-radius: var(--rm-radius-lg);
  box-shadow: var(--rm-shadow-lg);
  padding: var(--rm-space-6);
  width: 100%;
  max-width: 440px;
  outline: none;
  color: var(--rm-color-text-primary);
}

.rm-modal-header {
  display: flex;
  align-items: flex-start;
  gap: var(--rm-space-3);
  margin-bottom: var(--rm-space-5);
}
.rm-modal-icon {
  width: 24px;
  height: 24px;
  color: var(--rm-color-warning-deep);
  flex-shrink: 0;
  margin-top: 2px;
}
.rm-modal-title {
  font-size: 18px;
  font-weight: 600;
  margin: 0 0 var(--rm-space-1);
  line-height: 1.4;
  color: var(--rm-color-text-primary);
}
.rm-modal-desc {
  font-size: 13px;
  line-height: 1.6;
  color: var(--rm-color-text-secondary);
  margin: 0;
}

.rm-modal-form {
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-4);
}

.rm-field {
  display: flex;
  flex-direction: column;
  gap: var(--rm-space-2);
}
.rm-field-label {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  font-size: 12px;
  font-weight: 500;
  color: var(--rm-color-text-secondary);
}
.rm-field-hint {
  font-size: 11px;
  font-weight: 400;
  color: var(--rm-color-text-tertiary);
}
.rm-field-error {
  font-size: 12px;
  color: var(--rm-color-error-deep);
  margin: 0;
}

.rm-input {
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
.rm-input:hover {
  border-color: #4096ff;
}
.rm-input:focus {
  border-color: var(--rm-color-primary);
  box-shadow: 0 0 0 4px var(--rm-color-primary-soft);
}
.rm-input:disabled {
  background: var(--rm-color-auditor-surface);
  color: var(--rm-color-text-disabled);
  cursor: not-allowed;
}
.rm-input--error,
.rm-input--error:hover,
.rm-input--error:focus {
  border-color: var(--rm-color-error);
  box-shadow: 0 0 0 4px var(--rm-color-error-soft);
}

/* 强度指示：3 段 bar */
.rm-strength {
  display: flex;
  align-items: center;
  gap: var(--rm-space-2);
  font-size: 11px;
  color: var(--rm-color-text-tertiary);
}
.rm-strength-track {
  display: flex;
  gap: 3px;
  flex: 0 0 auto;
}
.rm-strength-bar {
  display: block;
  width: 32px;
  height: 3px;
  border-radius: 2px;
  background: var(--rm-color-hairline);
  transition: background var(--rm-duration-instant) var(--rm-ease-out);
}
.rm-strength--1 .rm-strength-bar:nth-child(1) {
  background: var(--rm-color-warning);
}
.rm-strength--2 .rm-strength-bar:nth-child(-n + 2) {
  background: var(--rm-color-primary);
}
.rm-strength--3 .rm-strength-bar {
  background: var(--rm-color-success);
}
.rm-strength--1 .rm-strength-label {
  color: var(--rm-color-warning-deep);
  font-weight: 500;
}
.rm-strength--2 .rm-strength-label {
  color: var(--rm-color-primary-deep);
  font-weight: 500;
}
.rm-strength--3 .rm-strength-label {
  color: var(--rm-color-success-deep);
  font-weight: 500;
}

.rm-banner {
  display: flex;
  gap: var(--rm-space-2);
  align-items: flex-start;
  padding: var(--rm-space-3) var(--rm-space-3);
  border-radius: var(--rm-radius-sm);
  font-size: 13px;
  line-height: 1.5;
}
.rm-banner-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
  margin-top: 2px;
}
.rm-banner--error {
  background: var(--rm-color-error-soft);
  border: 1px solid var(--rm-color-error-border);
  color: var(--rm-color-error-deep);
}

.rm-btn {
  height: 36px;
  padding: 0 var(--rm-space-4);
  font-family: var(--rm-font-sans);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  border-radius: var(--rm-radius-sm);
  border: 1px solid transparent;
  transition: background var(--rm-duration-instant) var(--rm-ease-out);
}
.rm-btn:focus-visible {
  outline: 2px solid var(--rm-color-primary);
  outline-offset: 2px;
}
.rm-btn--primary {
  background: var(--rm-color-primary);
  color: #ffffff;
}
.rm-btn--primary:hover:not(:disabled) {
  background: var(--rm-color-primary-deep);
}
.rm-btn--primary:active:not(:disabled) {
  background: #003eb3;
}
.rm-btn:disabled {
  background: var(--rm-color-auditor-surface);
  color: var(--rm-color-text-disabled);
  border: 1px solid var(--rm-color-hairline);
  cursor: not-allowed;
  opacity: 1;
}

.rm-modal-submit {
  width: 100%;
  margin-top: var(--rm-space-1);
}

.rm-modal-foot {
  margin: var(--rm-space-4) 0 0;
  padding-top: var(--rm-space-3);
  border-top: 1px solid var(--rm-color-hairline);
  font-size: 12px;
  color: var(--rm-color-text-tertiary);
}
.rm-mono {
  font-family: var(--rm-font-mono);
  color: var(--rm-color-text-secondary);
  font-size: 12px;
}

@media (max-width: 480px) {
  .rm-modal {
    padding: var(--rm-space-4);
  }
  .rm-modal-title {
    font-size: 16px;
  }
}
</style>
