import { createRouter, createWebHistory } from 'vue-router';
import { ensureLoaded, hasRole } from './store/session.js';

const routes = [
  { path: '/', redirect: '/inbox' },
  { path: '/login', component: () => import('./pages/Login.vue'), meta: { public: true } },
  { path: '/key-init', component: () => import('./pages/KeyInit.vue') },
  { path: '/send', component: () => import('./pages/Send.vue') },
  { path: '/inbox', component: () => import('./pages/Inbox.vue') },
  { path: '/decrypt/:fileId', component: () => import('./pages/Decrypt.vue') },
  { path: '/outbox', component: () => import('./pages/Outbox.vue') },
  { path: '/admin/files', component: () => import('./pages/AdminFiles.vue'), meta: { roles: ['SYS_ADMIN'] } },
  { path: '/admin/users', component: () => import('./pages/AdminUsers.vue'), meta: { roles: ['SYS_ADMIN'] } },
  { path: '/audit', component: () => import('./pages/Audit.vue'), meta: { roles: ['SECURITY_AUDITOR', 'SYS_ADMIN'] } },
  { path: '/security-events', component: () => import('./pages/SecurityEvents.vue'), meta: { roles: ['SECURITY_AUDITOR', 'SYS_ADMIN'] } },
  { path: '/selftest', component: () => import('./pages/SelfTest.vue'), meta: { public: true } },
];

const router = createRouter({ history: createWebHistory(), routes });

router.beforeEach(async (to) => {
  if (to.meta.public) return true;
  const user = await ensureLoaded();
  if (!user) return { path: '/login', query: { redirect: to.fullPath } };
  if (to.meta.roles && !to.meta.roles.some((r) => hasRole(r))) return { path: '/inbox' };
  return true;
});

export default router;
