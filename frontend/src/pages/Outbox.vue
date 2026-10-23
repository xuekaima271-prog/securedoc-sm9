<script setup>
import { ref, onMounted } from 'vue';
import { filesApi } from '../api/index.js';
import { fmtSize, fmtTime } from '../utils/fmt.js';

const items = ref([]);
const msg = ref('');

async function load() {
  try { items.value = await filesApi.outbox(); }
  catch (e) { msg.value = e.message; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>发件箱</h2>
    <p class="sub">你发起的密文投递记录（服务器侧仅保存密文与摘要）。</p>
    <div class="msg err" v-if="msg">{{ msg }}</div>
    <table v-if="items.length">
      <thead><tr><th>状态</th><th>密文大小</th><th>分块</th><th>时间</th><th>编号</th></tr></thead>
      <tbody>
        <tr v-for="f in items" :key="f.fileId">
          <td><span class="tag" :class="{ green: f.status === 'AVAILABLE' }">{{ f.status === 'AVAILABLE' ? '已投递' : f.status }}</span></td>
          <td>{{ fmtSize(f.totalSize) }}</td>
          <td>{{ f.chunkCount }}</td>
          <td>{{ fmtTime(f.createdAt) }}</td>
          <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty"><div class="icon">📮</div>暂无发送记录</div>
  </div>
</template>
