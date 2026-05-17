// PR-S65：export.ts 单元测试。
//
// 覆盖：
//   - parseFilenameFromCD 三种格式（quoted / bare / 空）
//   - downloadExport 拼 query 时跳过 undefined / 空字符串
//   - 401 时抛 Error（不静默）
//   - 成功路径触发 a.click

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { authStore } from '@/store/auth';
import { downloadExport, parseFilenameFromCD } from './export';

// fetch + URL + a.click 的 stub
const origFetch = global.fetch;
const origCreateObjectURL = URL.createObjectURL;
const origRevokeObjectURL = URL.revokeObjectURL;

beforeEach(() => {
  authStore.set({ token: 'jwt-xxx', username: 'a', role: 'SUPER_ADMIN', userId: 'u' });
  URL.createObjectURL = vi.fn(() => 'blob://fake');
  URL.revokeObjectURL = vi.fn();
});

afterEach(() => {
  global.fetch = origFetch;
  URL.createObjectURL = origCreateObjectURL;
  URL.revokeObjectURL = origRevokeObjectURL;
  authStore.clear();
});

describe('parseFilenameFromCD', () => {
  it('quoted filename', () => {
    expect(parseFilenameFromCD('attachment; filename="assets-20260515.csv"')).toBe('assets-20260515.csv');
  });
  it('bare filename', () => {
    expect(parseFilenameFromCD('attachment; filename=findings.json')).toBe('findings.json');
  });
  it('null / 无 filename → null', () => {
    expect(parseFilenameFromCD(null)).toBeNull();
    expect(parseFilenameFromCD('attachment')).toBeNull();
  });
});

describe('downloadExport', () => {
  function mockFetchOK(headers: Record<string, string> = {}) {
    global.fetch = vi.fn(async () => new Response(new Blob(['data']), {
      status: 200,
      headers: { 'Content-Disposition': 'attachment; filename="assets-x.csv"', ...headers },
    })) as typeof fetch;
  }

  it('拼 query 时跳过 undefined / 空字符串', async () => {
    mockFetchOK();
    await downloadExport('assets', 'csv', {
      kind: 'host',
      project_id: '',
      keyword: undefined,
      min_age_days: '7',
    });
    const fetchMock = global.fetch as ReturnType<typeof vi.fn>;
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toBe('/api/v1/export/assets?format=csv&kind=host&min_age_days=7');
  });

  it('Authorization 头带 Bearer + 当前 token', async () => {
    mockFetchOK();
    await downloadExport('findings', 'json');
    const fetchMock = global.fetch as ReturnType<typeof vi.fn>;
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer jwt-xxx');
  });

  it('非 2xx 响应抛 Error 含 body', async () => {
    global.fetch = vi.fn(async () => new Response('{"error":"FORBIDDEN"}', {
      status: 403,
      statusText: 'Forbidden',
    })) as typeof fetch;
    await expect(downloadExport('assets', 'csv')).rejects.toThrow(/FORBIDDEN/);
  });

  it('成功路径触发 a.click 用 filename', async () => {
    mockFetchOK();
    const clickSpy = vi.fn();
    const origCreate = document.createElement.bind(document);
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = origCreate(tag) as HTMLAnchorElement;
      if (tag === 'a') el.click = clickSpy;
      return el;
    });
    await downloadExport('assets', 'csv');
    expect(clickSpy).toHaveBeenCalledOnce();
  });
});
