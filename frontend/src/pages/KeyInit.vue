<script setup>
import { ref, onBeforeUnmount, onMounted } from 'vue';
import { keysApi } from '../api/index.js';
import { refreshUser } from '../store/session.js';
import { getPrivateKeyState, protectLegacyPrivateKey, savePrivateKey } from '../store/idb.js';

const status = ref(null);
const localKeyState = ref('missing');
const msg = ref('');
const msgType = ref('info');
const busy = ref(false);
const protectionPassword = ref('');
const protectionConfirmation = ref('');
const accountPassword = ref('');

function deviceFingerprint() {
  return `${navigator.userAgent}|${navigator.language}|${screen.width}x${screen.height}`;
}

async function load() {
  try {
    status.value = await keysApi.myStatus();
    localKeyState.value = await getPrivateKeyState(status.value.userId);
  } catch (e) {
    msgType.value = 'err';
    msg.value = e.message || '无法读取密钥状态';
  }
}

function clearPasswords() {
  accountPassword.value = '';
  protectionPassword.value = '';
  protectionConfirmation.value = '';
}

function validatePassword() {
  if (protectionPassword.value.length < 12) {
    msgType.value = 'err';
    msg.value = '本地保护口令至少需要 12 个字符。';
    return false;
  }
  if (protectionPassword.value !== protectionConfirmation.value) {
    msgType.value = 'err';
    msg.value = '两次输入的本地保护口令不一致。';
    return false;
  }
  return true;
}

async function doInit() {
  if (!validatePassword()) return;
  if (!accountPassword.value) {
    msgType.value = 'err';
    msg.value = '签发私钥需要再次验证登录密码。';
    return;
  }
  busy.value = true; msg.value = '';
  try {
    const res = await keysApi.init(deviceFingerprint(), accountPassword.value);
    await savePrivateKey({
      userId: res.userId, identity: res.identity,
      privateKeyPackage: res.privateKeyPackage, createdAt: res.issuedAt || new Date().toISOString(),
    }, protectionPassword.value);
    msgType.value = 'ok';
    msg.value = `签发成功，本地私钥已使用保护口令加密保存（issueId=${res.issueId}）。`;
    await load();
    await refreshUser();
  } catch (e) {
    msgType.value = 'err';
    msg.value = e.message || '初始化失败（KGC 是否在 :8081 运行？）';
  } finally {
    clearPasswords();
    busy.value = false;
  }
}

async function migrateLegacy() {
  if (!status.value || !validatePassword()) return;
  busy.value = true; msg.value = '';
  try {
    await protectLegacyPrivateKey(status.value.userId, protectionPassword.value);
    localKeyState.value = await getPrivateKeyState(status.value.userId);
    msgType.value = 'ok';
    msg.value = '旧版本地私钥已加密迁移；未重新向 KGC 签发私钥。';
  } catch (e) {
    msgType.value = 'err';
    msg.value = e.message || '旧版私钥迁移失败';
  } finally {
    clearPasswords();
    busy.value = false;
  }
}

onMounted(load);
onBeforeUnmount(clearPasswords);
</script>

<template>
  <div class="card fade-in">
    <h2>我的密钥</h2>
    <p class="sub">首次使用需向 KGC 申请 SM9 用户私钥。私钥包到达浏览器后会使用本地保护口令加密保存到 IndexedDB；口令不会保存或发送给服务端。换设备时可重新签发（同一身份签出的私钥完全一致）。</p>
    <div v-if="status">
      <div class="row"><b>SM9 身份标识：</b><span class="mono">{{ status.identity }}</span></div>
      <div class="row" style="margin-top: 0.5rem;">
        <b>服务端密钥状态：</b>
        <span class="tag" :class="{ green: status.initialized }">{{ status.keyStatus }}</span>
        <b>本地私钥：</b>
        <span class="tag" :class="{ green: localKeyState === 'encrypted', red: localKeyState === 'legacy' }">{{ localKeyState === 'encrypted' ? '已加密保存' : (localKeyState === 'legacy' ? '需迁移' : '未保存') }}</span>
      </div>
    </div>
    <div class="msg" :class="msgType" v-if="msg">{{ msg }}</div>
    <div style="margin-top: 1rem; max-width: 440px;">
      <label for="account-password">登录密码（签发时验证）</label>
      <input id="account-password" v-model="accountPassword" type="password" autocomplete="current-password" :disabled="busy" />
      <label for="key-password">本地保护口令（至少 12 个字符）</label>
      <input id="key-password" v-model="protectionPassword" type="password" autocomplete="new-password" maxlength="1024" :disabled="busy" />
      <label for="key-password-confirm">确认本地保护口令</label>
      <input id="key-password-confirm" v-model="protectionConfirmation" type="password" autocomplete="new-password" maxlength="1024" :disabled="busy" />
    </div>
    <div class="row" style="margin-top: 1rem;">
      <button :disabled="busy" @click="doInit">
        {{ busy ? '处理中…' : (localKeyState === 'encrypted' ? '重新签发并替换本地加密包' : '初始化我的 SM9 私钥') }}
      </button>
      <button v-if="localKeyState === 'legacy'" class="ghost" :disabled="busy" @click="migrateLegacy">加密迁移旧版私钥</button>
    </div>
    <p v-if="localKeyState === 'legacy'" class="sub" style="margin-top: .7rem;">检测到旧版未加密私钥。选择“加密迁移旧版私钥”不会重新签发或删除现有私钥。</p>
  </div>
</template>
