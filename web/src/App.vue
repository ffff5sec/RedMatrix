<script setup lang="ts">
import { ref, computed } from 'vue';
import { authStore } from '@/store/auth';
import LoginPanel from '@/views/LoginPanel.vue';
import ProfilePanel from '@/views/ProfilePanel.vue';
import APIKeysPanel from '@/views/APIKeysPanel.vue';
import UsersPanel from '@/views/UsersPanel.vue';
import ProjectsPanel from '@/views/ProjectsPanel.vue';

type Tab = 'login' | 'profile' | 'apikeys' | 'users' | 'projects';
const active = ref<Tab>(authStore.isAuthed() ? 'profile' : 'login');

const tabs = computed(() => [
  { key: 'login', label: '登录', enabled: !authStore.isAuthed() },
  { key: 'profile', label: '个人', enabled: authStore.isAuthed() },
  { key: 'apikeys', label: 'API Keys', enabled: authStore.isAuthed() },
  // PA 也开放：能看自己加入的项目
  { key: 'projects', label: '项目', enabled: authStore.isAuthed() },
  { key: 'users', label: '用户管理', enabled: authStore.isSuperAdmin() || authStore.isAuditor() },
]);

function onLoggedIn() {
  active.value = 'profile';
}
function onLoggedOut() {
  active.value = 'login';
}
</script>

<template>
  <div class="topbar">
    <span class="brand">RedMatrix · Identity 演示</span>
    <span v-if="authStore.isAuthed()" class="row">
      <span class="muted">{{ authStore.username }}</span>
      <span class="badge blue">{{ authStore.role }}</span>
    </span>
  </div>

  <div class="container">
    <div class="tabs">
      <button
        v-for="t in tabs"
        :key="t.key"
        class="tab"
        :class="{ active: active === t.key }"
        :disabled="!t.enabled"
        @click="t.enabled && (active = t.key as Tab)"
      >
        {{ t.label }}
      </button>
    </div>

    <LoginPanel v-if="active === 'login'" @logged-in="onLoggedIn" />
    <ProfilePanel v-else-if="active === 'profile'" @logged-out="onLoggedOut" />
    <APIKeysPanel v-else-if="active === 'apikeys'" />
    <ProjectsPanel v-else-if="active === 'projects'" />
    <UsersPanel v-else-if="active === 'users'" />
  </div>
</template>
