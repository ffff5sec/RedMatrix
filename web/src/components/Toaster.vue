<script setup lang="ts">
// Toaster —— 全局 Toast 渲染单例。
//
// 视觉：
//   - 固定右上 top: 16px / right: 16px；竖排堆叠
//   - 4 种 type 颜色：success 绿 / info 蓝 / warning 琥珀 / error 红
//   - 进入：右滑入 + 渐显；离开：上移 + 渐隐
//   - 鼠标悬停 → 暂停（不实现；MVP 简化）；点 × 立刻关
//
// 用法：在 App.vue 顶层放一个 <Toaster />；任何组件用 useToast() 推消息。
import { useToast, type Toast } from '@/composables/useToast';

const { toasts, close } = useToast();

function iconFor(type: Toast['type']): string {
  switch (type) {
    case 'success': return '✓';
    case 'error':   return '✕';
    case 'warning': return '!';
    case 'info':    return 'i';
  }
}
</script>

<template>
  <Teleport to="body">
    <div class="toaster" role="status" aria-live="polite">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          class="toast"
          :class="`toast-${t.type}`"
          role="alert"
        >
          <span class="toast-icon" aria-hidden="true">{{ iconFor(t.type) }}</span>
          <span class="toast-msg">{{ t.message }}</span>
          <button class="toast-close" :aria-label="`关闭通知`" @click="close(t.id)">
            ×
          </button>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toaster {
  position: fixed;
  top: 16px;
  right: 16px;
  z-index: 9999;
  display: flex;
  flex-direction: column;
  gap: 8px;
  pointer-events: none;
  /* 限制最大宽度让长消息换行而不顶到屏外 */
  max-width: min(420px, calc(100vw - 32px));
}

.toast {
  pointer-events: auto;
  display: grid;
  grid-template-columns: 24px 1fr auto;
  align-items: start;
  gap: 10px;
  padding: 10px 12px;
  border-radius: 6px;
  background: #fff;
  border: 1px solid var(--border, #e2e8f0);
  box-shadow:
    0 4px 6px -1px rgba(0, 0, 0, 0.06),
    0 2px 4px -2px rgba(0, 0, 0, 0.06);
  font-size: 13px;
  line-height: 1.5;
  color: var(--text, #1f2937);
}

.toast-icon {
  display: inline-flex;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 12px;
  color: #fff;
  flex-shrink: 0;
  margin-top: 1px;
}

.toast-msg {
  word-break: break-word;
  white-space: pre-wrap;
}

.toast-close {
  background: transparent;
  border: none;
  color: var(--muted, #9ca3af);
  cursor: pointer;
  font-size: 18px;
  line-height: 1;
  padding: 0 4px;
  margin-top: -2px;
}

.toast-close:hover {
  color: var(--text, #1f2937);
}

/* === 颜色按 type 分档 === */
.toast-success { border-left: 3px solid #22c55e; }
.toast-success .toast-icon { background: #22c55e; }

.toast-error { border-left: 3px solid #ef4444; }
.toast-error .toast-icon { background: #ef4444; }

.toast-warning { border-left: 3px solid #f59e0b; }
.toast-warning .toast-icon { background: #f59e0b; }

.toast-info { border-left: 3px solid #3b82f6; }
.toast-info .toast-icon { background: #3b82f6; }

/* === transition === */
.toast-enter-from {
  opacity: 0;
  transform: translateX(20px);
}
.toast-enter-active,
.toast-leave-active {
  transition: opacity 200ms ease, transform 200ms ease;
}
.toast-leave-to {
  opacity: 0;
  transform: translateY(-8px);
}
</style>
