<script setup lang="ts">
import { useRouter } from 'vue-router';

const router = useRouter();
</script>

<template>
  <div class="forbidden">
    <h2>403 · 无权限</h2>
    <p class="muted">当前角色无法访问该页面。</p>
    <button class="btn" @click="router.push({ name: 'profile' })">返回个人中心</button>
  </div>
</template>

<style scoped>
.forbidden {
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
