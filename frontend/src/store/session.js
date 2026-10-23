import { reactive } from 'vue';
import { authApi } from '../api/index.js';

// 全局会话状态（轻量，不引额外状态库）。
export const session = reactive({
  user: null,        // {userId, username, roles, keyInitialized}
  loaded: false,     // 是否已尝试从后端拉取过当前用户
});

export function hasRole(role) {
  return !!session.user && Array.isArray(session.user.roles) && session.user.roles.includes(role);
}

/** 首次进入时拉取当前登录用户（基于 Cookie 会话）。失败=未登录。 */
export async function ensureLoaded() {
  if (session.loaded) return session.user;
  try {
    session.user = await authApi.me();
  } catch {
    session.user = null;
  } finally {
    session.loaded = true;
  }
  return session.user;
}

export async function refreshUser() {
  try { session.user = await authApi.me(); } catch { session.user = null; }
  return session.user;
}

export function setUser(u) { session.user = u; session.loaded = true; }
export function clearUser() { session.user = null; }
