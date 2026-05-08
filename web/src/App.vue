<script setup lang="ts">
// App.vue —— 顶层 router-view + 全局 Toaster。
//
// LoginPanel 的 logged-in 事件由本组件转换为 router.push：
// 守卫拦截匿名访问时会把目标路径写到 query.redirect，登录成功后跳回去。
import { useRoute, useRouter } from 'vue-router';
import Toaster from '@/components/Toaster.vue';

const router = useRouter();
const route = useRoute();

function onLoggedIn() {
  const redirect = route.query.redirect;
  if (typeof redirect === 'string' && redirect.startsWith('/')) {
    router.push(redirect);
    return;
  }
  router.push({ name: 'dashboard' });
}
</script>

<template>
  <router-view v-slot="{ Component }">
    <component :is="Component" v-if="Component" @logged-in="onLoggedIn" />
  </router-view>
  <Toaster />
</template>
