// PR-S20-C：AppShell 导航 role gating smoke。
//
// 验：SA / Auditor 看到所有 9 个导航；PA 看不到 "节点" / "用户管理"。
// 不挂 Vue Router（只 stub router-link / router-view），让 mount 不需真路由。

import { beforeEach, describe, expect, it } from 'vitest';
import { mount } from '@vue/test-utils';

import { authStore } from '@/store/auth';
import AppShell from './AppShell.vue';

beforeEach(() => {
  localStorage.clear();
  authStore.clear();
});

function mountAppShell() {
  return mount(AppShell, {
    global: {
      stubs: {
        // router-link 渲染成 a 标签，保留 default slot 让 textContent 可断言
        'router-link': {
          props: ['to'],
          template: '<a class="nav-link"><slot /></a>',
        },
        'router-view': true,
      },
      // useRouter / useRoute 不会被 mount-time 求值；按需 stub provide
      mocks: {
        $route: { name: 'dashboard' },
      },
    },
  });
}

function navLabels(wrapper: ReturnType<typeof mountAppShell>): string[] {
  return wrapper.findAll('a.nav-link').map((a) => a.text().trim());
}

describe('AppShell 导航 role gating', () => {
  it('SA 看到所有 13 个 nav（含 节点 + 用户管理 + 套件 + 通知 + 漏洞 + 插件库）', () => {
    authStore.set({ token: 't', username: 'admin', role: 'SUPER_ADMIN', userId: 'u' });
    const w = mountAppShell();
    const labels = navLabels(w);
    expect(labels).toContain('概览');
    expect(labels).toContain('节点');
    expect(labels).toContain('用户管理');
    expect(labels).toContain('套件');
    expect(labels).toContain('通知');
    expect(labels).toContain('漏洞');
    expect(labels).toContain('插件库');
    expect(labels.length).toBe(13);
  });

  it('TenantAuditor 看到 节点 + 用户管理', () => {
    authStore.set({ token: 't', username: 'auditor', role: 'TENANT_AUDITOR', userId: 'u' });
    const w = mountAppShell();
    const labels = navLabels(w);
    expect(labels).toContain('节点');
    expect(labels).toContain('用户管理');
  });

  it('PlatformAuditor 看到 节点 + 用户管理', () => {
    authStore.set({ token: 't', username: 'pa', role: 'PLATFORM_AUDITOR', userId: 'u' });
    const w = mountAppShell();
    const labels = navLabels(w);
    expect(labels).toContain('节点');
    expect(labels).toContain('用户管理');
  });

  it('PA 看不到 节点 + 用户管理（仅 10 项，含套件 + 通知 + 漏洞）', () => {
    authStore.set({ token: 't', username: 'pa', role: 'PROJECT_ADMIN', userId: 'u' });
    const w = mountAppShell();
    const labels = navLabels(w);
    expect(labels).not.toContain('节点');
    expect(labels).not.toContain('用户管理');
    expect(labels).toContain('扫描'); // 业务必备
    expect(labels).toContain('套件');
    expect(labels).toContain('资产');
    expect(labels).toContain('结果搜索');
    expect(labels).toContain('通知');
    expect(labels).toContain('漏洞');
    expect(labels.length).toBe(10);
  });
});

describe('AppShell topbar', () => {
  it('显示当前用户名 + role chip', () => {
    authStore.set({ token: 't', username: 'alice', role: 'SUPER_ADMIN', userId: 'u' });
    const w = mountAppShell();
    expect(w.text()).toContain('alice');
    expect(w.text()).toContain('SUPER_ADMIN');
  });
});
