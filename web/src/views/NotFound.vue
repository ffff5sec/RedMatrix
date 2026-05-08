<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from 'vue-router';

import { authStore } from '@/store/auth';

const router = useRouter();
const target = computed(() => (authStore.isAuthed() ? { name: 'profile' } : { name: 'login' }));
</script>

<template>
  <div class="notfound">
    <h2>404 · 页面不存在</h2>
    <p class="muted">链接可能已过期或被移除。</p>
    <button class="btn" @click="router.push(target)">返回</button>
  </div>
</template>

<style scoped>
.notfound {
  text-align: center;
  padding: 48px 16px;
}
.muted {
  color: var(--muted, #6b7280);
  margin: 8px 0 24px;
}
.btn {
  padding: 8px 16px;
  border-radius: 6px;
  background: var(--accent, #2563eb);
  color: #fff;
  border: none;
  cursor: pointer;
}
</style>
