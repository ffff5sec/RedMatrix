// PR-S20-B：router authGuard 单测。验未登录 / 已登录 / 角色不足三态。

import { beforeEach, describe, expect, it } from 'vitest';
import type { RouteLocationNormalized } from 'vue-router';

import { authStore } from '@/store/auth';
import { authGuard } from './index';

beforeEach(() => {
  localStorage.clear();
  authStore.clear();
});

// 最小可用的 RouteLocationNormalized stub（authGuard 只读 name / meta / fullPath）
function fakeRoute(name: string, meta: Record<string, unknown>, fullPath = '/x'): RouteLocationNormalized {
  return {
    name,
    meta,
    fullPath,
    path: fullPath,
    params: {},
    query: {},
    hash: '',
    matched: [],
    redirectedFrom: undefined,
  } as unknown as RouteLocationNormalized;
}

describe('authGuard 未登录', () => {
  it('access requiresAuth route → 跳 /login + 带 redirect query', () => {
    const r = authGuard(fakeRoute('dashboard', { requiresAuth: true }, '/dashboard'));
    expect(r).toEqual({ name: 'login', query: { redirect: '/dashboard' } });
  });
  it('access /login → 放行', () => {
    const r = authGuard(fakeRoute('login', {}));
    expect(r).toBe(true);
  });
  it('access 不 requiresAuth route → 放行', () => {
    const r = authGuard(fakeRoute('not-found', {}));
    expect(r).toBe(true);
  });
});

describe('authGuard 已登录', () => {
  beforeEach(() => {
    authStore.set({ token: 'jwt', username: 'admin', role: 'SUPER_ADMIN', userId: 'u' });
  });
  it('access /login → 跳 /', () => {
    const r = authGuard(fakeRoute('login', {}));
    expect(r).toEqual({ path: '/' });
  });
  it('access requiresAuth route → 放行', () => {
    const r = authGuard(fakeRoute('dashboard', { requiresAuth: true }));
    expect(r).toBe(true);
  });
});

describe('authGuard 角色门', () => {
  it('SA 访问 requiresRoles=[SA,Auditor] → 放行', () => {
    authStore.set({ token: 't', username: 'a', role: 'SUPER_ADMIN', userId: 'u' });
    const r = authGuard(fakeRoute('nodes', {
      requiresAuth: true,
      requiresRoles: ['SUPER_ADMIN', 'TENANT_AUDITOR', 'PLATFORM_AUDITOR'],
    }));
    expect(r).toBe(true);
  });
  it('PA 访问 requiresRoles=[SA,Auditor] → 跳 /403', () => {
    authStore.set({ token: 't', username: 'a', role: 'PROJECT_ADMIN', userId: 'u' });
    const r = authGuard(fakeRoute('nodes', {
      requiresAuth: true,
      requiresRoles: ['SUPER_ADMIN', 'TENANT_AUDITOR', 'PLATFORM_AUDITOR'],
    }));
    expect(r).toEqual({ name: 'forbidden' });
  });
  it('requiresRoles 空数组 → 不挡（与 undefined 同语义）', () => {
    authStore.set({ token: 't', username: 'a', role: 'PROJECT_ADMIN', userId: 'u' });
    const r = authGuard(fakeRoute('x', { requiresAuth: true, requiresRoles: [] }));
    expect(r).toBe(true);
  });
});
