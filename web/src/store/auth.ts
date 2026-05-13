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
  isProjectAdmin(): boolean {
    return this.role === 'PROJECT_ADMIN';
  },
  isAuditor(): boolean {
    return this.role === 'TENANT_AUDITOR' || this.role === 'PLATFORM_AUDITOR';
  },
  // PR-S43: 写操作可见性 helper —— 与后端 writers (SA+PA) 对齐 (HLD §4.3
  // Auditor 只读)。UI 写按钮全部用 isWriter() 隐藏 Auditor 视图，避免点击后才
  // 看到 PERMISSION_DENIED toast。
  isWriter(): boolean {
    return this.role === 'SUPER_ADMIN' || this.role === 'PROJECT_ADMIN';
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
