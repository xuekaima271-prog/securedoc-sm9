<script setup>
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { authApi } from '../api/index.js';
import { clearUser } from '../store/session.js';

const router = useRouter();
const oldPassword = ref('');
const newPassword = ref('');
const confirmPassword = ref('');
const msg = ref('');
const msgType = ref('info');
const busy = ref(false);

function fail(text) {
  msgType.value = 'err';
  msg.value = text;
  return false;
}

// 与后端 ChangePasswordRequest 同口径：新密码 8–64 位、两次一致、不得与旧密码相同。
function validate() {
  if (!oldPassword.value) return fail('请输入旧密码。');
  if (newPassword.value.length < 8) return fail('新密码至少 8 位。');
  if (newPassword.value.length > 64) return fail('新密码至多 64 位。');
  if (newPassword.value === oldPassword.value) return fail('新密码不能与旧密码相同。');
  if (newPassword.value !== confirmPassword.value) return fail('两次输入的新密码不一致。');
  return true;
}

async function submit() {
  if (!validate()) return;
  busy.value = true;
  msg.value = '';
  try {
    await authApi.changePassword(oldPassword.value, newPassword.value);
    // 后端已作废当前会话：清本地会话态并回登录页，必须用新密码重新登录。
    msgType.value = 'ok';
    msg.value = '密码已修改，正在跳转登录页，请用新密码重新登录…';
    clearUser();
    setTimeout(() => router.push('/login'), 800);
  } catch (e) {
    msgType.value = 'err';
    msg.value = e.message || '修改失败，请重试';
    busy.value = false;
  } finally {
    oldPassword.value = '';
    newPassword.value = '';
    confirmPassword.value = '';
  }
}
</script>

<template>
  <div class="card fade-in">
    <h2>修改密码</h2>
    <p class="sub">修改当前账号的登录密码。须先验证旧密码；修改成功后当前会话立即失效，需要用新密码重新登录。</p>
    <div class="msg" :class="msgType" v-if="msg">{{ msg }}</div>
    <div class="mt-4 form-narrow">
      <label for="old-password">旧密码</label>
      <input id="old-password" v-model="oldPassword" type="password" autocomplete="current-password" :disabled="busy" />
      <label for="new-password">新密码（至少 8 位）</label>
      <input id="new-password" v-model="newPassword" type="password" autocomplete="new-password" maxlength="64" :disabled="busy" />
      <label for="confirm-password">确认新密码</label>
      <input id="confirm-password" v-model="confirmPassword" type="password" autocomplete="new-password" maxlength="64" :disabled="busy" @keyup.enter="submit" />
    </div>
    <div class="row mt-4">
      <button :disabled="busy" @click="submit">{{ busy ? '处理中…' : '确认修改' }}</button>
    </div>
  </div>
</template>
