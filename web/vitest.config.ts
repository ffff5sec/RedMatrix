// vitest 配置（PR-S20-A）—— 与 vite.config.ts 共享 plugins / alias。
//
// 用 happy-dom 替代 jsdom：体积小 3x、启动快 ~10x，覆盖 Vue 组件挂载 + DOM
// query 已足够；如遇 jsdom-only API 再切回。
import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    include: ['src/**/*.{test,spec}.ts'],
    // localStorage / setTimeout 等 DOM 全局自带；setup 文件可后续加
  },
});
