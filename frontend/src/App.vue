<script setup>
import { computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { session, hasRole, clearUser } from './store/session.js';
import { authApi } from './api/index.js';
import { roleName } from './utils/fmt.js';

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
  <div class="app">
    <header v-if="session.user" class="nav">
      <span class="brand">🔐 端到端加密文档投递</span>
      <nav>
        <router-link to="/send">📤 发送文件</router-link>
        <router-link to="/inbox">📥 收件箱</router-link>
        <router-link to="/outbox">🗂 发件箱</router-link>
        <router-link to="/key-init">🔑 我的密钥</router-link>
        <router-link v-if="hasRole('SYS_ADMIN')" to="/admin/users">👥 用户管理</router-link>
        <router-link v-if="hasRole('SYS_ADMIN')" to="/admin/files">🗄 密文记录</router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SECURITY_AUDITOR')" to="/audit">📋 审计</router-link>
        <router-link v-if="hasRole('SYS_ADMIN') || hasRole('SECURITY_AUDITOR')" to="/security-events">🚨 安全事件</router-link>
        <router-link to="/selftest">🧪 国密自检</router-link>
      </nav>
      <span class="user">
        <span class="avatar">{{ initial }}</span>
        <span>{{ session.user.username }} <small style="color:#9ca3af">{{ roleText }}</small></span>
        <button class="link" @click="logout">退出</button>
      </span>
    </header>
    <main class="content">
      <router-view :key="route.fullPath" />
    </main>
  </div>
</template>
