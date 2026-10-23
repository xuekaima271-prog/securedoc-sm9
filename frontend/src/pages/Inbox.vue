<script setup>
import { ref, onMounted } from 'vue';
import { filesApi, keysApi } from '../api/index.js';
import { fmtSize, fmtTime } from '../utils/fmt.js';

const items = ref([]);
const names = ref({});   // userId -> 显示名
const msg = ref('');

async function load() {
  try {
    const [inbox, users] = await Promise.all([filesApi.inbox(), keysApi.recipients()]);
    items.value = inbox;
    names.value = Object.fromEntries(users.map((u) => [u.userId, u.realName || u.username]));
  } catch (e) { msg.value = e.message; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>收件箱</h2>
    <p class="sub">发给你的加密文件。文件名等元数据也是密文，解密后才可见。</p>
    <div class="msg err" v-if="msg">{{ msg }}</div>
    <table v-if="items.length">
      <thead><tr><th>发送人</th><th>密文大小</th><th>分块</th><th>时间</th><th>编号</th><th></th></tr></thead>
      <tbody>
        <tr v-for="f in items" :key="f.fileId">
          <td><span class="avatar" style="width:22px;height:22px;font-size:.7rem;margin-right:.4rem">{{ (names[f.senderId] || '?').slice(0,1) }}</span>{{ names[f.senderId] || `用户${f.senderId}` }}</td>
          <td>{{ fmtSize(f.totalSize) }}</td>
          <td>{{ f.chunkCount }}</td>
          <td>{{ fmtTime(f.createdAt) }}</td>
          <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
          <td><router-link :to="`/decrypt/${f.fileId}`"><button class="ghost">🔓 解密下载</button></router-link></td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty"><div class="icon">📭</div>暂无收到的文件</div>
  </div>
</template>
