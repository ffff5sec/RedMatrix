// PR-S65：HTTP 导出下载助手。
//
// 后端 /api/v1/export/{resource}?format=csv|json|xlsx 要求 Authorization
// Bearer 头；浏览器 <a href> 标签下载没法自动加这个头，所以走 fetch + blob
// + URL.createObjectURL → <a download>.click() 的标准模式触发"另存为"。
//
// resource：'assets' / 'findings'
// format：'csv' / 'json' / 'xlsx'
// params：filter 字段，undefined / 空字符串自动跳过

import { authStore } from '@/store/auth';

export type ExportResource = 'assets' | 'findings';
export type ExportFormat = 'csv' | 'json' | 'xlsx';

export async function downloadExport(
  resource: ExportResource,
  format: ExportFormat,
  params: Record<string, string | undefined | null> = {},
): Promise<void> {
  const q = new URLSearchParams({ format });
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== '') {
      q.set(k, String(v));
    }
  }
  const url = `/api/v1/export/${resource}?${q.toString()}`;
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${authStore.token}` },
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.text();
      if (body) detail = body;
    } catch {
      // 忽略读 body 失败
    }
    throw new Error(detail);
  }
  const filename = parseFilenameFromCD(res.headers.get('Content-Disposition')) ?? `${resource}.${format}`;
  const blob = await res.blob();
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(blobUrl);
}

// parseFilenameFromCD 从 Content-Disposition: attachment; filename="x.csv" 提
// 取文件名；非 quoted 也兜底。
export function parseFilenameFromCD(cd: string | null): string | null {
  if (!cd) return null;
  const quoted = cd.match(/filename="([^"]+)"/);
  if (quoted) return quoted[1];
  const bare = cd.match(/filename=([^;]+)/);
  if (bare) return bare[1].trim();
  return null;
}
