<script setup>
import { ref, defineAsyncComponent } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { authApi } from '../api/index.js';
import { setUser } from '../store/session.js';
import Icon from '../components/Icon.vue';

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
  <div class="login-wrap fade-in">
    <section class="login-brand">
      <Icon name="seal" class="seal-mark" />
      <h1>端到端加密<br />文档投递</h1>
      <p>文件在浏览器内以 SM4 加密、密钥经 SM9 按身份封装，审计以 SM3 哈希链留痕。服务器与管理员全程只见密文。</p>
      <div class="chips">
        <span class="chip">SM9 身份加密</span>
        <span class="chip">SM4 分块加密</span>
        <span class="chip">SM3 哈希链审计</span>
      </div>
    </section>
    <div class="card login-card">
      <h2>登录</h2>
      <p class="sub">使用你的账号进入投递控制台。</p>
      <form @submit.prevent="submit">
        <label>用户名</label>
        <input v-model="username" autocomplete="username" />
        <label>密码</label>
        <input v-model="password" type="password" autocomplete="current-password" />
        <div class="msg err" v-if="err">{{ err }}</div>
        <button type="submit" class="big login-btn" :disabled="busy">
          {{ busy ? '登录中…' : '登录' }}
        </button>
      </form>
      <DemoAccounts v-if="DemoAccounts" @fill="fill" />
    </div>
  </div>
</template>
