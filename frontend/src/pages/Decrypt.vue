<script setup>
import { ref, computed, watch, onBeforeUnmount } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { filesApi } from '../api/index.js';
import { session } from '../store/session.js';
import { loadPrivateKey } from '../store/idb.js';
import { secureDoc, b64ToBytes } from '../crypto/index.js';
import { callWorker, workerAvailable } from '../crypto/worker-client.js';
import { fmtSize } from '../utils/fmt.js';
import { createDecryptedFile } from '../utils/decrypted-file.js';

const route = useRoute();
const router = useRouter();
const fileId = computed(() => String(route.params.fileId));

const steps = ref([]);
const msg = ref('');
const msgType = ref('info');
const busy = ref(false);
const percent = ref(0);
const unlockPassword = ref('');
const unlockRequired = ref(true);
let generation = 0;
const result = ref(null);   // {fileName, size, url, remark, preview:{type,src|text}}

function step(t) { steps.value.push(t); }

function clearResult() {
  generation++;
  result.value?.dispose();
  result.value = null;
  unlockPassword.value = '';
  unlockRequired.value = true;
  busy.value = false;
  percent.value = 0;
  steps.value = [];
  msg.value = '';
}

async function run() {
  if (busy.value) return;
  if (!unlockPassword.value) {
    unlockRequired.value = true;
    msgType.value = 'err';
    msg.value = '请输入本地保护口令后解密。口令只在本机内存中使用，不会发送到服务器。';
    return;
  }
  result.value?.dispose();
  const current = ++generation;
  const id = fileId.value;
  let privateKeyBytes;
  let dek;
  let keyRec;
  busy.value = true; steps.value = []; msg.value = ''; result.value = null; percent.value = 0;
  try {
    step('读取本地 SM9 私钥');
    const unlocking = loadPrivateKey(session.user.userId, unlockPassword.value);
    unlockPassword.value = '';
    keyRec = await unlocking;
    privateKeyBytes = b64ToBytes(keyRec.privateKeyPackage);
    keyRec.privateKeyPackage = '';
    if (generation !== current) return;
    percent.value = 8;

    step('定位收件箱记录');
    const inbox = await filesApi.inbox();
    if (generation !== current) return;
    const entry = inbox.find((f) => f.fileId === id);
    if (!entry) throw new Error('收件箱中找不到该文件（可能未就绪或你不是接收人）');
    percent.value = 14;

    step('获取我的密钥信封 → SM9 解封文件密钥');
    const env = await filesApi.keyEnvelope(id);
    if (generation !== current) return;
    const useWorker = workerAvailable();   // FE-1：解密在后台线程执行，不可用时回退主线程
    const unwrapReq = { keyEnvelope: env.keyEnvelope, identity: keyRec.identity, privateKeyBytes };
    dek = useWorker ? await callWorker('unwrapDek', unwrapReq) : secureDoc.unwrapDek(unwrapReq);
    privateKeyBytes.fill(0);
    if (generation !== current) return;
    percent.value = 22;

    const parts = [];   // Uint8Array 分块列表（Blob 直接拼接，避免巨型数组展开/整体拷贝）
    for (let i = 0; i < entry.chunkCount; i++) {
      step(`分块 ${i + 1}/${entry.chunkCount}：下载 → SM3 校验 → SM4 解密`);
      const { bytes, digestB64, ivB64 } = await filesApi.downloadChunk(id, i);
      if (generation !== current) return;
      const req = { dek, ivB64, ciphertext: bytes, expectDigestB64: digestB64 };
      const plain = useWorker ? await callWorker('openChunk', req) : Uint8Array.from(secureDoc.openChunk(req));
      if (generation !== current) { plain.fill(0); return; }
      parts.push(plain);
      percent.value = 22 + Math.round(((i + 1) / entry.chunkCount) * 73);
    }

    step('解密元数据（文件名/MIME/备注）');
    const metaReq = { dek, encryptedMetadata: entry.encryptedMetadata };
    const meta = useWorker ? await callWorker('openMetadata', metaReq) : secureDoc.openMetadata(metaReq);
    if (generation !== current) return;
    percent.value = 100;

    const nextResult = await createDecryptedFile(parts, meta);
    parts.forEach((part) => part.fill(0));
    if (generation !== current) { nextResult.dispose(); return; }
    result.value = nextResult;
    msgType.value = 'ok';
    msg.value = '';
    unlockRequired.value = false;
  } catch (e) {
    if (generation !== current) return;
    msgType.value = 'err';
    msg.value = e.message || '解密失败';
  } finally {
    if (keyRec) keyRec.privateKeyPackage = '';
    privateKeyBytes?.fill(0);
    dek?.fill(0);
    if (generation === current) {
      unlockPassword.value = '';
      busy.value = false;
    }
  }
}

watch(fileId, clearResult);
onBeforeUnmount(clearResult);
</script>

<template>
  <div class="card fade-in">
    <h2>解密下载</h2>
    <p class="sub">全部步骤在浏览器内完成：SM9 解封密钥 → 逐块 SM3 校验 → SM4 解密。<span class="mono">fileId={{ fileId.slice(0, 8) }}…</span></p>

    <div class="progress" v-if="busy || percent > 0"><div class="bar" :style="{ width: percent + '%' }"></div></div>
    <ol class="steps">
      <li v-for="(s, i) in steps" :key="i" :class="{ doing: busy && i === steps.length - 1 }">{{ s }}</li>
    </ol>
    <div class="msg" :class="msgType" v-if="msg">{{ msg }}</div>

    <div v-if="unlockRequired" class="row" style="margin-top:.8rem; max-width:520px; align-items:end;">
      <div style="flex:1; min-width:220px;">
        <label for="unlock-password">本地保护口令</label>
        <input id="unlock-password" v-model="unlockPassword" type="password" autocomplete="current-password" :disabled="busy"
               placeholder="输入“我的密钥”页设置的口令" @keyup.enter="run" />
      </div>
      <button class="ghost" :disabled="busy" @click="run">解锁并解密</button>
    </div>

    <div v-if="result" class="done fade-in">
      <div class="icon">🔓</div>
      <div class="title">解密成功：{{ result.fileName }}（{{ fmtSize(result.size) }}）</div>
      <div v-if="result.remark" class="msg info" style="text-align:left">📝 加密备注：{{ result.remark }}</div>
      <img v-if="result.preview?.type === 'image'" :src="result.preview.src"
           style="max-width:100%; max-height:340px; border-radius:8px; margin:.6rem 0; box-shadow:var(--shadow-lg)" />
      <pre v-else-if="result.preview?.type === 'text'"
           style="text-align:left; background:#fff; border:1px solid var(--line); border-radius:8px; padding:.8rem; max-height:280px; overflow:auto; font-size:.82rem">{{ result.preview.text }}</pre>
      <div style="margin-top:.6rem">
        <a :href="result.url" :download="result.fileName"><button class="big">⬇ 下载「{{ result.fileName }}」</button></a>
      </div>
    </div>

    <div class="row" style="margin-top: 1rem;">
      <button v-if="result" class="ghost" :disabled="busy" @click="clearResult">锁定并清除预览</button>
      <button class="link" @click="router.push('/inbox')">← 返回收件箱</button>
    </div>
  </div>
</template>
