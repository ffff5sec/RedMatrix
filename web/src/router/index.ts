// router/index.ts —— Vue Router 配置 + 全局守卫。
//
// 路由模型（PR-W2 起）：
//   /login           独立页（无 AppShell）；已 authed → 重定向 /
//   /                AppShell 布局；index → /profile
//   /profile         个人中心 + 改密 + 退出
//   /api-keys        当前用户 API Key
//   /projects        Project CRUD（PA 视角过滤）
//   /nodes           Node CRUD（SA / Auditor）
//   /users           用户管理（SA / Auditor）
//   /403             角色不足兜底
//   /:catchAll       404
//
// 守卫职责：
//   1. requiresAuth + 无 token → /login（带 redirect query 让登录后跳回）
//   2. 有 token 访问 /login → /
//   3. requiresRole + 当前 role 不在白名单 → /403
import {
  createRouter,
  createWebHashHistory,
  type RouteRecordRaw,
  type RouteLocationNormalized,
  type RouteLocationRaw,
} from 'vue-router';

import { authStore } from '@/store/auth';

import AppShell from '@/layouts/AppShell.vue';
import LoginPanel from '@/views/LoginPanel.vue';
import Dashboard from '@/views/Dashboard.vue';
import ProfilePanel from '@/views/ProfilePanel.vue';
import NodeDetail from '@/views/NodeDetail.vue';
import ScansPanel from '@/views/ScansPanel.vue';
import ScanDetail from '@/views/ScanDetail.vue';
import ScanResults from '@/views/ScanResults.vue';
import ScanSuitesPanel from '@/views/ScanSuitesPanel.vue';
import SuiteRunDetail from '@/views/SuiteRunDetail.vue';
import NotificationsPanel from '@/views/NotificationsPanel.vue';
import FindingsPanel from '@/views/FindingsPanel.vue';
import FindingDetail from '@/views/FindingDetail.vue';
import PluginsPanel from '@/views/PluginsPanel.vue';
import FingerprintsPanel from '@/views/FingerprintsPanel.vue';
import AuditPanel from '@/views/AuditPanel.vue';
import AssetsPanel from '@/views/AssetsPanel.vue';
import AssetDetail from '@/views/AssetDetail.vue';
import AssetEventsPanel from '@/views/AssetEventsPanel.vue';
import APIKeysPanel from '@/views/APIKeysPanel.vue';
import ProjectsPanel from '@/views/ProjectsPanel.vue';
import NodesPanel from '@/views/NodesPanel.vue';
import UsersPanel from '@/views/UsersPanel.vue';
import Forbidden from '@/views/Forbidden.vue';
import NotFound from '@/views/NotFound.vue';

// 角色字符串与 store/auth.ts + identity proto 一致。
const ROLE_SA = 'SUPER_ADMIN';
const ROLE_TENANT_AUDITOR = 'TENANT_AUDITOR';
const ROLE_PLATFORM_AUDITOR = 'PLATFORM_AUDITOR';

const adminAndAuditors = [ROLE_SA, ROLE_TENANT_AUDITOR, ROLE_PLATFORM_AUDITOR];

declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean;
    requiresRoles?: string[];
    title?: string;
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: LoginPanel,
    meta: { title: '登录' },
  },
  {
    path: '/',
    component: AppShell,
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/dashboard' },
      {
        path: 'dashboard',
        name: 'dashboard',
        component: Dashboard,
        meta: { requiresAuth: true, title: '概览' },
      },
      {
        path: 'profile',
        name: 'profile',
        component: ProfilePanel,
        meta: { requiresAuth: true, title: '个人' },
      },
      {
        path: 'api-keys',
        name: 'api-keys',
        component: APIKeysPanel,
        meta: { requiresAuth: true, title: 'API Keys' },
      },
      {
        path: 'projects',
        name: 'projects',
        component: ProjectsPanel,
        meta: { requiresAuth: true, title: '项目' },
      },
      {
        path: 'scans',
        name: 'scans',
        component: ScansPanel,
        meta: { requiresAuth: true, title: '扫描任务' },
      },
      {
        path: 'scans/:id',
        name: 'scan-detail',
        component: ScanDetail,
        meta: { requiresAuth: true, title: '任务详情' },
      },
      {
        path: 'scan-results',
        name: 'scan-results',
        component: ScanResults,
        meta: { requiresAuth: true, title: '结果搜索' },
      },
      {
        path: 'scan-suites',
        name: 'scan-suites',
        component: ScanSuitesPanel,
        meta: { requiresAuth: true, title: '扫描套件' },
      },
      {
        path: 'scan-suite-runs/:id',
        name: 'suite-run-detail',
        component: SuiteRunDetail,
        meta: { requiresAuth: true, title: '套件运行详情' },
      },
      {
        path: 'assets',
        name: 'assets',
        component: AssetsPanel,
        meta: { requiresAuth: true, title: '资产' },
      },
      {
        path: 'notifications',
        name: 'notifications',
        component: NotificationsPanel,
        meta: { requiresAuth: true, title: '通知' },
      },
      {
        path: 'findings',
        name: 'findings',
        component: FindingsPanel,
        meta: { requiresAuth: true, title: '漏洞' },
      },
      {
        path: 'findings/:id',
        name: 'finding-detail',
        component: FindingDetail,
        meta: { requiresAuth: true, title: '漏洞详情' },
      },
      {
        path: 'plugins',
        name: 'plugins',
        component: PluginsPanel,
        meta: { requiresAuth: true, requiresRoles: [ROLE_SA], title: '插件库' },
      },
      {
        path: 'fingerprints',
        name: 'fingerprints',
        component: FingerprintsPanel,
        meta: { requiresAuth: true, title: '指纹库' },
      },
      {
        path: 'audit',
        name: 'audit',
        component: AuditPanel,
        meta: { requiresAuth: true, requiresRoles: adminAndAuditors, title: '审计日志' },
      },
      {
        path: 'assets/:id',
        name: 'asset-detail',
        component: AssetDetail,
        meta: { requiresAuth: true, title: '资产详情' },
      },
      {
        path: 'asset-events',
        name: 'asset-events',
        component: AssetEventsPanel,
        meta: { requiresAuth: true, title: '资产变更时间线' },
      },
      {
        path: 'nodes',
        name: 'nodes',
        component: NodesPanel,
        meta: { requiresAuth: true, requiresRoles: adminAndAuditors, title: '节点' },
      },
      {
        path: 'nodes/:id',
        name: 'node-detail',
        component: NodeDetail,
        meta: { requiresAuth: true, requiresRoles: adminAndAuditors, title: '节点详情' },
      },
      {
        path: 'users',
        name: 'users',
        component: UsersPanel,
        meta: { requiresAuth: true, requiresRoles: adminAndAuditors, title: '用户管理' },
      },
      {
        path: '403',
        name: 'forbidden',
        component: Forbidden,
        meta: { requiresAuth: true, title: '无权限' },
      },
    ],
  },
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: NotFound,
    meta: { title: '页面不存在' },
  },
];

export const router = createRouter({
  // hash 模式：MVP 不依赖后端路由 fallback，刷新 / 直链 / 静态 hosting 都稳。
  history: createWebHashHistory(),
  routes,
});

// authGuard 是路由守卫纯函数，导出供 vitest 单测（PR-S20-B）。
// 通用规则：
//   - 已登录访 /login → /
//   - 未登录且 meta.requiresAuth → /login?redirect=...
//   - meta.requiresRoles 不命中当前 role → /403
//   - 其它 → 放行
export function authGuard(to: RouteLocationNormalized): RouteLocationRaw | true {
  const authed = authStore.isAuthed();

  // 已登录访问 /login → /
  if (to.name === 'login' && authed) {
    return { path: '/' };
  }

  // 需登录但没 token
  if (to.meta.requiresAuth && !authed) {
    return {
      name: 'login',
      query: { redirect: to.fullPath },
    };
  }

  // 角色不足
  if (to.meta.requiresRoles && to.meta.requiresRoles.length > 0) {
    if (!to.meta.requiresRoles.includes(authStore.role)) {
      return { name: 'forbidden' };
    }
  }

  return true;
}

router.beforeEach(authGuard);

router.afterEach((to) => {
  if (to.meta.title) {
    document.title = `${to.meta.title} · RedMatrix`;
  } else {
    document.title = 'RedMatrix';
  }
});
