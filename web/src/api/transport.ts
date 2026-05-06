import { createConnectTransport } from '@connectrpc/connect-web';
import { createPromiseClient, type Interceptor } from '@connectrpc/connect';
import { IdentityService } from '@/gen/proto/redmatrix/identity/v1/identity_connect';
import { authStore } from '@/store/auth';

// 自动附 Authorization: Bearer <jwt>。
// authStore.token 是 reactive；每次请求重读，登出后立即停用。
const authInterceptor: Interceptor = (next) => async (req) => {
  const t = authStore.token;
  if (t) {
    req.header.set('Authorization', `Bearer ${t}`);
  }
  return next(req);
};

// 任意 RPC 返 AUTH_TOKEN_VERSION_MISMATCH / AUTH_TOKEN_EXPIRED → 自动清 token，
// 用户被弹回 Login。
const tvWatchdogInterceptor: Interceptor = (next) => async (req) => {
  try {
    return await next(req);
  } catch (err) {
    const msg = (err as Error).message ?? '';
    if (
      msg.includes('AUTH_TOKEN_VERSION_MISMATCH') ||
      msg.includes('AUTH_TOKEN_EXPIRED') ||
      msg.includes('AUTH_FAILED')
    ) {
      authStore.clear();
    }
    throw err;
  }
};

export const transport = createConnectTransport({
  // 同源相对路径走 Vite proxy；生产同域部署时同样工作。
  baseUrl: '',
  interceptors: [authInterceptor, tvWatchdogInterceptor],
});

export const identityClient = createPromiseClient(IdentityService, transport);
