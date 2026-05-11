// PR-S20-B：authStore 单元测试。验角色判定 / set / clear / 持久化。

import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from './auth';

beforeEach(() => {
  // 每用例前清掉 localStorage 和 store 状态，让断言可重复
  localStorage.clear();
  authStore.clear();
});

describe('authStore.isAuthed', () => {
  it('未 set token 时返 false', () => {
    expect(authStore.isAuthed()).toBe(false);
  });
  it('set token 后返 true', () => {
    authStore.set({ token: 'jwt-xxx', username: 'admin', role: 'SUPER_ADMIN', userId: 'u-1' });
    expect(authStore.isAuthed()).toBe(true);
  });
});

describe('authStore.role 判定', () => {
  it('SA → isSuperAdmin true', () => {
    authStore.set({ token: 't', username: 'a', role: 'SUPER_ADMIN', userId: 'u' });
    expect(authStore.isSuperAdmin()).toBe(true);
    expect(authStore.isAuditor()).toBe(false);
  });
  it('TenantAuditor → isAuditor true', () => {
    authStore.set({ token: 't', username: 'a', role: 'TENANT_AUDITOR', userId: 'u' });
    expect(authStore.isAuditor()).toBe(true);
    expect(authStore.isSuperAdmin()).toBe(false);
  });
  it('PlatformAuditor → isAuditor true', () => {
    authStore.set({ token: 't', username: 'a', role: 'PLATFORM_AUDITOR', userId: 'u' });
    expect(authStore.isAuditor()).toBe(true);
  });
  it('PA → 既非 SA 也非 Auditor', () => {
    authStore.set({ token: 't', username: 'a', role: 'PROJECT_ADMIN', userId: 'u' });
    expect(authStore.isSuperAdmin()).toBe(false);
    expect(authStore.isAuditor()).toBe(false);
  });
});

describe('authStore 持久化', () => {
  it('set 写 localStorage; reload 时新实例可恢复', () => {
    authStore.set({ token: 'jwt-1', username: 'admin', role: 'SUPER_ADMIN', userId: 'u-1', expiresAt: '2030-01-01T00:00:00Z' });
    const raw = localStorage.getItem('redmatrix.demo.auth');
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.token).toBe('jwt-1');
    expect(parsed.expiresAt).toBe('2030-01-01T00:00:00Z');
  });
  it('clear 清 localStorage 和 store', () => {
    authStore.set({ token: 't', username: 'a', role: 'SUPER_ADMIN', userId: 'u' });
    authStore.clear();
    expect(authStore.token).toBe('');
    expect(authStore.username).toBe('');
    expect(authStore.role).toBe('');
    expect(localStorage.getItem('redmatrix.demo.auth')).toBeNull();
  });
});
