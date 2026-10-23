<script setup>
import { computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { session, hasRole, clearUser } from './store/session.js';
import { authApi } from './api/index.js';
import { roleName } from './utils/fmt.js';
import Icon from './components/Icon.vue';

const router = useRouter();
const route = useRoute();

const roleText = computed(() => (session.user?.roles || []).map(roleName).join('·'));
const initial = computed(() => (session.user?.username || '?').slice(0, 1).toUpperCase());

async function logout() {
  try { await authApi.logout(); } catch { /* ignore */ }
  clearUser();
  router.push('/login');
}
</script>

<template>
  <div class="app" :class="{ 'app--auth': session.user }">
    <aside v-if="session.user" class="sidebar">
      <div class="side-brand">
        <Icon name="seal" class="seal-mark" />
        <div class="b-text">
          <div class="b-name">SecureDoc</div>
          <div class="b-sub">国密 SM9 · 端到端加密投递</div>
        </div>
      </div>
      <nav class="side-nav">
        <router-link to="/send" title="发送文件"><Icon name="send" /><span class="nav-label">发送文件</span></router-link>
        <router-link to="/inbox" title="收件箱"><Icon name="inbox" /><span class="nav-label">收件箱</span></router-link>
        <router-link to="/outbox" title="发件箱"><Icon name="outbox" /><span class="nav-label">发件箱</span></router-link>
        <router-link to="/key-init" title="我的密钥"><Icon name="key" /><span class="nav-label">我的密钥</span></router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SUPER_ADMIN')" to="/admin/users" title="用户管理"><Icon name="users" /><span class="nav-label">用户管理</span></router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SUPER_ADMIN')" to="/admin/files" title="密文记录"><Icon name="database" /><span class="nav-label">密文记录</span></router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SUPER_ADMIN') || hasRole('SECURITY_AUDITOR')" to="/audit" title="审计"><Icon name="audit" /><span class="nav-label">审计</span></router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SUPER_ADMIN') || hasRole('SECURITY_AUDITOR')" to="/security-events" title="安全事件"><Icon name="shield" /><span class="nav-label">安全事件</span></router-link>
        <router-link to="/selftest" title="国密自检"><Icon name="flask" /><span class="nav-label">国密自检</span></router-link>
      </nav>
      <div class="side-foot">
        <div class="user-chip">
          <span class="avatar">{{ initial }}</span>
          <span class="u-meta">{{ session.user.username }}<small class="u-roles">{{ roleText }}</small></span>
        </div>
        <button class="ghost logout-btn" @click="logout"><Icon name="logout" /><span class="nav-label">退出登录</span></button>
      </div>
    </aside>
    <main class="content">
      <router-view :key="route.fullPath" />
    </main>
  </div>
</template>
