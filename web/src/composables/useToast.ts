// useToast —— 全局 Toast 通知系统（PR-W4）。
//
// 用法：
//   import { useToast } from '@/composables/useToast';
//   const toast = useToast();
//   toast.success('节点已注册');
//   toast.error('请求失败：xxx');
//   toast.info(...);
//   toast.warning(...);
//
// 设计：
//   - 模块级 ref 共享所有 useToast() 实例；Toaster 组件监听同一个数组
//   - 自动 dismiss 时长按 type 分档：success 3s / info 4s / warning 5s / error 6s
//   - 手动 dismiss：close(id)
//   - 同时显示上限 5 条；超出后最早的被立即挤出
//   - 每条带唯一 id（递增）；transition 由 Toaster 内部管理

import { ref } from 'vue';

export type ToastType = 'success' | 'error' | 'info' | 'warning';

export interface Toast {
  id: number;
  type: ToastType;
  message: string;
  /** 显式覆盖默认 dismiss 时长（毫秒）；0 = 不自动 dismiss。 */
  duration: number;
}

const MAX_VISIBLE = 5;

const DEFAULT_DURATION_MS: Record<ToastType, number> = {
  success: 3000,
  info: 4000,
  warning: 5000,
  error: 6000,
};

const toasts = ref<Toast[]>([]);
let nextId = 1;
const timers = new Map<number, ReturnType<typeof setTimeout>>();

function push(type: ToastType, message: string, duration?: number): number {
  const id = nextId++;
  const t: Toast = {
    id,
    type,
    message,
    duration: duration ?? DEFAULT_DURATION_MS[type],
  };
  toasts.value.push(t);

  // 容量控制：超出立即弹出最早的
  while (toasts.value.length > MAX_VISIBLE) {
    const dropped = toasts.value.shift();
    if (dropped) clearTimer(dropped.id);
  }

  // 自动 dismiss（duration=0 → 永驻）
  if (t.duration > 0) {
    const timer = setTimeout(() => close(id), t.duration);
    timers.set(id, timer);
  }
  return id;
}

function close(id: number) {
  const idx = toasts.value.findIndex((t) => t.id === id);
  if (idx >= 0) toasts.value.splice(idx, 1);
  clearTimer(id);
}

function clearTimer(id: number) {
  const timer = timers.get(id);
  if (timer) {
    clearTimeout(timer);
    timers.delete(id);
  }
}

export function useToast() {
  return {
    /** 列表（reactive）；Toaster 组件渲染入口。 */
    toasts,
    success: (msg: string, duration?: number) => push('success', msg, duration),
    error: (msg: string, duration?: number) => push('error', msg, duration),
    info: (msg: string, duration?: number) => push('info', msg, duration),
    warning: (msg: string, duration?: number) => push('warning', msg, duration),
    /** 主动关闭某条 toast。 */
    close,
  };
}
