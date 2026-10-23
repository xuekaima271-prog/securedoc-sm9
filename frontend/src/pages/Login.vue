<script setup>
import { ref, defineAsyncComponent } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { authApi } from '../api/index.js';
import { setUser } from '../store/session.js';

const router = useRouter();
const route = useRoute();
const username = ref('');
const password = ref('');
const err = ref('');
const busy = ref(false);

// 演示账号一键填充（含统一口令）仅开发构建动态加载该组件；生产构建此分支被消除，组件与口令均不打包。
const DemoAccounts = import.meta.env.DEV
  ? defineAsyncComponent(() => import('./DemoAccounts.vue'))
  : null;
function fill(u, pw) { username.value = u; password.value = pw; }

async function submit() {
  err.value = '';
  busy.value = true;
  try {
    const user = await authApi.login(username.value, password.value);
    setUser(user);
    router.push(route.query.redirect || '/send');
  } catch (e) {
    err.value = e.message || '登录失败';
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div style="max-width: 420px; margin: 8vh auto 0;" class="fade-in">
    <div style="text-align:center; margin-bottom:1rem;">
      <div style="font-size:2.6rem">🔐</div>
      <h2 style="margin:.3rem 0 .2rem">端到端加密文档投递</h2>
      <p class="sub" style="margin:0">国密 SM9 / SM4 / SM3 · 加解密全程在浏览器内 · 服务器不可解密</p>
    </div>
    <div class="card">
      <form @submit.prevent="submit">
        <label>用户名</label>
        <input v-model="username" autocomplete="username" />
        <label>密码</label>
        <input v-model="password" type="password" autocomplete="current-password" />
        <div class="msg err" v-if="err">{{ err }}</div>
        <button type="submit" class="big" :disabled="busy" style="margin-top: 1.1rem; width: 100%;">
          {{ busy ? '登录中…' : '登 录' }}
        </button>
      </form>
      <DemoAccounts v-if="DemoAccounts" @fill="fill" />
    </div>
  </div>
</template>
