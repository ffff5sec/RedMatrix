<script setup lang="ts">
// AppShell —— 已认证页面通用骨架。
//
// 视觉布局：
//   ┌─────────────────────────────────────────────┐
//   │ topbar  brand · spacer · user · role · logout│
//   ├─────────────┬───────────────────────────────┤
//   │ sidebar     │  <router-view />              │
//   │  · 个人      │                               │
//   │  · API Keys  │                               │
//   │  · 项目      │                               │
//   │  · 节点      │                               │
//   │  · 用户      │                               │
//   └─────────────┴───────────────────────────────┘
//
// 设计：
//   - 不含业务逻辑；纯导航壳
//   - sidebar 链接通过 router-link 自动挂 active class
//   - 顶部退出按钮调 IdentityService.Logout 走原 ProfilePanel 的逻辑：
//     这里不 import client，复用 store.clear() + push /login（与
//     ProfilePanel 行为等价；服务端 session 由后端 TTL 自然过期）
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { authStore } from '@/store/auth';

const router = useRouter();
const route = useRoute();

interface NavItem {
  name: string; // route name
  label: string;
  visible: boolean;
}

const navItems = computed<NavItem[]>(() => [
  { name: 'dashboard', label: '概览', visible: true },
  { name: 'profile', label: '个人', visible: true },
  { name: 'api-keys', label: 'API Keys', visible: true },
  { name: 'projects', label: '项目', visible: true },
  { name: 'scans', label: '扫描', visible: true },
  { name: 'scan-suites', label: '套件', visible: true },
  { name: 'scan-results', label: '结果搜索', visible: true },
  { name: 'assets', label: '资产', visible: true },
  { name: 'findings', label: '漏洞', visible: true },
  { name: 'notifications', label: '通知', visible: true },
  { name: 'plugins', label: '插件库', visible: authStore.isSuperAdmin() },
  { name: 'nodes', label: '节点', visible: authStore.isSuperAdmin() || authStore.isAuditor() },
  { name: 'users', label: '用户管理', visible: authStore.isSuperAdmin() || authStore.isAuditor() },
  { name: 'audit', label: '审计', visible: authStore.isSuperAdmin() || authStore.isAuditor() },
]);

function logout() {
  authStore.clear();
  router.push({ name: 'login' });
}
</script>

<template>
  <div class="shell">
    <header class="topbar">
      <span class="brand">RedMatrix</span>
      <span class="spacer" />
      <span class="user-meta">
        <span class="muted">{{ authStore.username }}</span>
        <span class="badge blue">{{ authStore.role }}</span>
        <button class="link-btn" @click="logout">退出</button>
      </span>
    </header>

    <div class="shell-body">
      <nav class="sidebar">
        <template v-for="item in navItems" :key="item.name">
          <router-link
            v-if="item.visible"
            :to="{ name: item.name }"
            class="nav-link"
            active-class="nav-link-active"
          >
            {{ item.label }}
          </router-link>
        </template>
      </nav>

      <main class="content">
        <!-- 仅 ProfilePanel emit logged-out；用动态 prop 名让其它 panel
             不收到该 listener，避免 Vue 把 unknown listener 警告刷在控制台 -->
        <router-view v-slot="{ Component }">
          <component
            :is="Component"
            v-if="Component"
            v-bind="route.name === 'profile' ? { onLoggedOut: logout } : {}"
          />
        </router-view>
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
}

.topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 20px;
  border-bottom: 1px solid var(--border, #e2e8f0);
  background: var(--surface, #fff);
}

.brand {
  font-weight: 600;
  font-size: 16px;
}

.spacer {
  flex: 1;
}

.user-meta {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
}

.muted {
  color: var(--muted, #6b7280);
}

.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  line-height: 1.4;
  background: rgba(59, 130, 246, 0.12);
  color: #2563eb;
}

.link-btn {
  background: transparent;
  border: none;
  color: var(--accent, #2563eb);
  cursor: pointer;
  font-size: 13px;
  padding: 4px 8px;
}

.link-btn:hover {
  text-decoration: underline;
}

.shell-body {
  display: flex;
  flex: 1;
  min-height: 0;
}

.sidebar {
  width: 200px;
  border-right: 1px solid var(--border, #e2e8f0);
  padding: 16px 8px;
  background: var(--surface, #fff);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.nav-link {
  display: block;
  padding: 8px 12px;
  border-radius: 6px;
  text-decoration: none;
  color: var(--text, #1f2937);
  font-size: 14px;
}

.nav-link:hover {
  background: var(--surface-hover, rgba(0, 0, 0, 0.04));
}

.nav-link-active {
  background: var(--accent, #2563eb);
  color: #fff;
}

.nav-link-active:hover {
  background: var(--accent, #2563eb);
}

.content {
  flex: 1;
  padding: 20px;
  overflow: auto;
  min-width: 0;
}
</style>
