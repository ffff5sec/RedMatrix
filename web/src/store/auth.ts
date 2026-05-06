import { reactive } from 'vue';

// 演示阶段把 JWT + 用户摘要放 localStorage。生产用 httpOnly cookie。
const STORAGE_KEY = 'redmatrix.demo.auth';

interface Persisted {
  token: string;
  username: string;
  role: string;
  userId: string;
  expiresAt?: string; // ISO
}

function load(): Persisted | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as Persisted;
  } catch {
    return null;
  }
}

const initial = load();

export const authStore = reactive({
  token: initial?.token ?? '',
  username: initial?.username ?? '',
  role: initial?.role ?? '',
  userId: initial?.userId ?? '',
  expiresAt: initial?.expiresAt ?? '',

  isAuthed(): boolean {
    return this.token !== '';
  },
  isSuperAdmin(): boolean {
    return this.role === 'SUPER_ADMIN';
  },
  isAuditor(): boolean {
    return this.role === 'TENANT_AUDITOR' || this.role === 'PLATFORM_AUDITOR';
  },
  set(p: Persisted) {
    this.token = p.token;
    this.username = p.username;
    this.role = p.role;
    this.userId = p.userId;
    this.expiresAt = p.expiresAt ?? '';
    localStorage.setItem(STORAGE_KEY, JSON.stringify(p));
  },
  clear() {
    this.token = '';
    this.username = '';
    this.role = '';
    this.userId = '';
    this.expiresAt = '';
    localStorage.removeItem(STORAGE_KEY);
  },
});
