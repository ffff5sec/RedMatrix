import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath, URL } from 'node:url';

// 反向代理 ConnectRPC 路径到本地 server :8080，避开浏览器 CORS。
// 后端按 LLD 默认监听 :8080；如改了端口设 RM_API_TARGET。
const apiTarget = process.env.RM_API_TARGET ?? 'http://localhost:8080';

// 用前缀通配：所有 /redmatrix.* 走后端 + /api/v1 走后端（webhook + export）
const proxyEntry = { target: apiTarget, changeOrigin: true };

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      // ConnectRPC：覆盖全部已注册 service（identity/tenancy/scan/asset/
      // audit/finding/notify/pluginpkg/export 等）。新 service 不需再加。
      '^/redmatrix\\..+': proxyEntry,
      // 非-RPC HTTP 端点（webhook + export 等）
      '/api/v1': proxyEntry,
    },
  },
});
