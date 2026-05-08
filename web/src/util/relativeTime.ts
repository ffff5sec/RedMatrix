// relativeTime —— 把过去/未来时间格式化为"X 秒前 / X 分钟前 / X 小时前"。
//
// 用于节点活性视图、token 过期倒计时等需要"动态"展示的场景。
//
// 设计：
//   - 输入支持 Date / number(ms epoch) / Timestamp({toDate(): Date})；
//     undefined → 返 placeholder "-"
//   - 单位档位：<60s / <60m / <24h / <30d / 否则 yyyy-MM-dd
//   - 中文 label；future 用"X 后"

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

type TimestampLike = Date | number | { toDate(): Date };

/**
 * formatRelativeTime 返回相对当前时刻的友好字串。
 * @param input 时间；undefined → placeholder
 * @param now  注入的 "now"（默认 Date.now()），便于测试
 * @param placeholder undefined 时显示
 */
export function formatRelativeTime(
  input: TimestampLike | undefined | null,
  now: number = Date.now(),
  placeholder: string = '-',
): string {
  if (input == null) return placeholder;
  const ms = toMs(input);
  if (ms == null) return placeholder;

  const diff = now - ms;
  const abs = Math.abs(diff);
  const future = diff < 0;
  const suffix = future ? '后' : '前';

  if (abs < 5 * SECOND) return future ? '即将' : '刚刚';
  if (abs < MINUTE) return `${Math.floor(abs / SECOND)} 秒${suffix}`;
  if (abs < HOUR) return `${Math.floor(abs / MINUTE)} 分钟${suffix}`;
  if (abs < DAY) return `${Math.floor(abs / HOUR)} 小时${suffix}`;
  if (abs < 30 * DAY) return `${Math.floor(abs / DAY)} 天${suffix}`;

  // 超过 30 天：直接给绝对日期（不再"X 个月前"，避免歧义）
  const d = new Date(ms);
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** formatAbsoluteTime 返回 ISO-like "yyyy-MM-dd HH:mm:ss"（本地时区）。tooltip 用。 */
export function formatAbsoluteTime(
  input: TimestampLike | undefined | null,
  placeholder: string = '-',
): string {
  if (input == null) return placeholder;
  const ms = toMs(input);
  if (ms == null) return placeholder;
  const d = new Date(ms);
  return (
    `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
    `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`
  );
}

function toMs(input: TimestampLike): number | null {
  if (input instanceof Date) return input.getTime();
  if (typeof input === 'number') return input;
  if (typeof input === 'object' && typeof (input as { toDate?: unknown }).toDate === 'function') {
    return (input as { toDate(): Date }).toDate().getTime();
  }
  return null;
}

function pad2(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}
