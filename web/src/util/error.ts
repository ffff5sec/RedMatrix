import { ConnectError } from '@connectrpc/connect';

// errorMessage 把 ConnectError / Error / unknown 转 UI 显示字符串。
export function errorMessage(err: unknown): string {
  if (err instanceof ConnectError) {
    // ConnectError.message 形如 "[code] error_code: message"
    return err.message;
  }
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}
