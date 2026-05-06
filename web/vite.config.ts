import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

// 反向代理 ConnectRPC 路径到本地 server :8080，避开浏览器 CORS。
// 后端按 LLD 默认监听 :8080；如改了端口设 RM_API_TARGET。
const apiTarget = process.env.RM_API_TARGET ?? 'http://localhost:8080';

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      '/redmatrix.identity.v1.IdentityService': {
        target: apiTarget,
        changeOrigin: true,
      },
      '/redmatrix.tenancy.v1.TenancyService': {
        target: apiTarget,
        changeOrigin: true,
      },
      // 后续 service 在此追加
    },
  },
});
