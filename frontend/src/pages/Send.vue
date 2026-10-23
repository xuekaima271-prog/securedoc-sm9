<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { keysApi, filesApi } from '../api/index.js';
import { secureDoc, b64ToBytes } from '../crypto/index.js';
import { callWorker, workerAvailable } from '../crypto/worker-client.js';
import { session } from '../store/session.js';
import { fmtSize } from '../utils/fmt.js';
import Icon from '../components/Icon.vue';

const router = useRouter();
const recipients = ref([]);
const selected = ref({});        // userId -> bool
const query = ref('');
const file = ref(null);
const remark = ref('');
const chunkKB = ref(0);          // 0 = 自动
const dragOver = ref(false);
const msg = ref('');
const msgType = ref('info');
const busy = ref(false);
const stage = ref('');           // 当前阶段文案
const percent = ref(0);
const done = ref(null);          // {fileId, count, chunks}

const shown = computed(() => {
  const q = query.value.trim().toLowerCase();
  if (!q) return recipients.value;
  return recipients.value.filter((r) =>
    r.username.toLowerCase().includes(q) || (r.realName || '').toLowerCase().includes(q));
});
const chosenCount = computed(() => recipients.value.filter((r) => selected.value[r.userId]).length);

/** 自动分块：>16MB 用 4MB 块（大文件少往返），否则 256KB */
function autoChunk(size) { return size > 16 * 1024 * 1024 ? 4 * 1024 : 256; }

async function load() { recipients.value = await keysApi.recipients(); }

function pickFile(f) { if (f) { file.value = f; done.value = null; msg.value = ''; } }
function onInput(e) { pickFile(e.target.files[0]); e.target.value = ''; }
function onDrop(e) { dragOver.value = false; pickFile(e.dataTransfer.files[0]); }
function toggle(r) { selected.value[r.userId] = !selected.value[r.userId]; }

function reset() {
  file.value = null; remark.value = ''; selected.value = {}; done.value = null;
  msg.value = ''; percent.value = 0; stage.value = '';
}

const paint = () => new Promise((r) => setTimeout(r, 30));   // 让浏览器先渲染进度再进同步加密

async function send() {
  msg.value = ''; done.value = null;
  const chosen = recipients.value.filter((r) => selected.value[r.userId]);
  if (!file.value) { msgType.value = 'err'; msg.value = '请先选择文件'; return; }
  if (chosen.length === 0) { msgType.value = 'err'; msg.value = '请至少选择一个接收人'; return; }
  const notReady = chosen.filter((r) => r.keyStatus === 'UNINITIALIZED');
  if (notReady.length) {
    msgType.value = 'warn';
    msg.value = `提示：${notReady.map((r) => r.realName || r.username).join('、')} 尚未初始化密钥，对方需先初始化才能解密。`;
  }

  busy.value = true; percent.value = 0;
  try {
    stage.value = '读取主公钥与文件…'; percent.value = 5; await paint();
    const mpkB64 = (await keysApi.masterPublicKey()).masterPublicKey;
    const masterPublicKeyBytes = b64ToBytes(mpkB64);
    const buf = new Uint8Array(await file.value.arrayBuffer());
    const metadata = {
      fileName: file.value.name, mimeType: file.value.type || 'application/octet-stream',
      remark: remark.value.trim(), originalSize: buf.length,
    };
    const kb = chunkKB.value > 0 ? chunkKB.value : autoChunk(buf.length);
    const recs = chosen.map((r) => ({ userId: r.userId, identity: r.identity }));

    let sealed = null;
    if (workerAvailable()) {
      // FE-1：加密在 Web Worker 后台线程执行——页面不卡顿，且逐块细分进度
      stage.value = '后台加密线程启动…'; percent.value = 8;
      try {
        sealed = await callWorker('seal', {
          fileBuffer: buf.buffer, metadata, recipients: recs,
          masterPublicKeyBytes, chunkSize: kb * 1024,
        }, {
          transfer: [buf.buffer],   // 零拷贝移交文件内容
          onProgress: (doneN, total) => {
            percent.value = 8 + Math.round((doneN / total) * 47);
            stage.value = doneN < total
              ? `SM4 加密分块 ${doneN}/${total}…`
              : `SM9 封装密钥信封（${recs.length} 个）…`;
          },
        });
      } catch (we) {
        // 仅对 Worker 基础设施故障回退主线程；密码学错误（如密钥不符）原样抛出
        if (!/Worker/i.test(we.message || '')) throw we;
        sealed = null;
      }
    }
    if (!sealed) {
      // 回退：主线程同步加密（Worker 不可用/异常；transfer 后原 buffer 已失效需重读）
      stage.value = `浏览器内 SM4 加密 + SM9 封装密钥（${recs.length} 个信封）…`; percent.value = 15; await paint();
      const buf2 = new Uint8Array(await file.value.arrayBuffer());
      sealed = secureDoc.sealFile({
        fileBytes: [...buf2], metadata, recipients: recs,
        masterPublicKeyBytes, chunkSize: kb * 1024,
      });
    }
    percent.value = 55;

    stage.value = '创建上传任务…'; await paint();
    const init = await filesApi.initUpload({
      encryptedMetadata: sealed.encryptedMetadata,
      chunkSize: sealed.chunkSize, chunkCount: sealed.chunkCount, totalSize: sealed.totalSize,
      recipients: sealed.recipients,
    });
    const fileId = init.fileId;

    for (const c of sealed.chunks) {
      stage.value = `上传密文分块 ${c.index + 1}/${sealed.chunkCount}…`;
      await filesApi.uploadChunk(fileId, c.index, c.ciphertext, c.digestB64, c.ivB64);
      percent.value = 55 + Math.round(((c.index + 1) / sealed.chunkCount) * 43);
    }
    stage.value = '完成投递…';
    await filesApi.complete(fileId);
    percent.value = 100; stage.value = '';
    done.value = { fileId, count: chosen.length, chunks: sealed.chunkCount };
    if (msgType.value !== 'warn') msg.value = '';
  } catch (e) {
    msgType.value = 'err';
    msg.value = e.message || '发送失败';
    stage.value = '';
  } finally {
    busy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>发送加密文件</h2>
    <p class="sub">文件在<strong>你的浏览器内</strong>完成 SM4 加密与 SM9 密钥封装，服务器全程只见密文。</p>

    <!-- 成功面板 -->
    <div v-if="done" class="done fade-in">
      <div class="icon"><Icon name="checkCircle" /></div>
      <div class="title">已加密投递给 {{ done.count }} 位接收人</div>
      <div class="mono">fileId = {{ done.fileId }} · {{ done.chunks }} 个密文分块 · 明文与密钥从未离开浏览器</div>
      <div class="row row-center mt-4">
        <button class="ghost" @click="router.push('/outbox')">查看发件箱</button>
        <button @click="reset">再发一份</button>
      </div>
    </div>

    <template v-else>
      <!-- ① 选文件：点击或拖拽 -->
      <label>① 文件</label>
      <div class="drop" :class="{ over: dragOver }"
           @click="$refs.fi.click()"
           @dragover.prevent="dragOver = true" @dragleave="dragOver = false" @drop.prevent="onDrop">
        <div class="icon"><Icon name="file" /></div>
        <div>点击选择文件，或拖拽到这里</div>
        <div class="hint">任意类型均可；大文件自动分块加密</div>
        <input ref="fi" type="file" style="display:none" @change="onInput" />
      </div>
      <div v-if="file" class="file-chip fade-in">
        <span class="fc-ic"><Icon name="file" /></span>
        <div class="grow">
          <div class="name">{{ file.name }}</div>
          <div class="meta">{{ fmtSize(file.size) }} · {{ file.type || '未知类型' }}</div>
        </div>
        <button class="link" @click="file = null">移除</button>
      </div>

      <!-- ② 选接收人：卡片点选 -->
      <label>② 接收人 <span style="color:var(--muted); font-weight:400">（点选，可多人；每人独立密钥信封）</span>
        <span v-if="chosenCount" class="tag blue" style="margin-left:.4rem">已选 {{ chosenCount }} 人</span>
      </label>
      <input v-if="recipients.length > 8" v-model="query" placeholder="搜索用户名/姓名…" style="margin-bottom:.5rem" />
      <div class="recips">
        <div v-for="r in shown" :key="r.userId" class="recip" :class="{ on: selected[r.userId] }"
             :title="r.identity" @click="toggle(r)">
          <span class="avatar">{{ (r.realName || r.username).slice(0, 1).toUpperCase() }}</span>
          <div class="who">
            <div class="n">{{ r.realName || r.username }}<small v-if="r.userId === session.user?.userId" style="color:var(--muted)">（我）</small></div>
            <div class="s"><span class="dot" :class="{ green: r.keyStatus !== 'UNINITIALIZED' }"></span>
              {{ r.keyStatus === 'UNINITIALIZED' ? '未初始化密钥' : '可接收' }}</div>
          </div>
        </div>
      </div>

      <!-- ③ 备注（可选，随元数据一起加密） -->
      <label>③ 备注 <span style="color:var(--muted); font-weight:400">（可选，同样端到端加密，仅接收人可见）</span></label>
      <input v-model="remark" maxlength="200" placeholder="例如：请查收本周方案" />

      <details class="adv">
        <summary>高级选项</summary>
        <label>分块大小（KB，0=自动：≤16MB 文件用 256KB，更大用 4MB）</label>
        <input type="number" v-model.number="chunkKB" min="0" style="max-width:220px" />
      </details>

      <!-- 进度与消息 -->
      <div v-if="busy || percent > 0" class="mt-4">
        <div class="progress" role="progressbar" :aria-valuenow="percent" aria-valuemin="0" aria-valuemax="100"><div class="bar" :style="{ width: percent + '%' }"></div></div>
        <div class="msg info" v-if="stage">{{ stage }}</div>
      </div>
      <div class="msg" :class="msgType" v-if="msg">{{ msg }}</div>

      <button class="big mt-4" :disabled="busy" @click="send">
        <Icon name="lock" />{{ busy ? '处理中…' : '加密并发送' }}
      </button>
    </template>
  </div>
</template>
