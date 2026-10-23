<script setup>
import { ref, onMounted } from 'vue';
import { adminApi } from '../api/index.js';

const items = ref([]);
const msg = ref('');

async function load() {
  try { items.value = await adminApi.files(); }
  catch (e) { msg.value = e.message; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>密文记录（管理员视角）</h2>
    <p class="sub">管理员可审计全部文件密文记录，但<strong>看不到明文</strong>：元数据是 SM4 密文、密钥是 SM9 信封——服务端与管理员都无法解密，这正是端到端加密的证明。</p>
    <div class="msg err" v-if="msg">{{ msg }}</div>
    <table v-if="items.length">
      <thead><tr><th>编号</th><th>发送人ID</th><th>状态</th><th>分块</th><th>接收人数</th><th>密文元数据（不可解）</th></tr></thead>
      <tbody>
        <tr v-for="f in items" :key="f.fileId">
          <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
          <td>{{ f.senderId }}</td>
          <td><span class="tag" :class="{ green: f.status === 'AVAILABLE' }">{{ f.status === 'AVAILABLE' ? '已投递' : f.status }}</span></td>
          <td>{{ f.chunkCount }}</td>
          <td>{{ f.recipientCount }}</td>
          <td class="mono">{{ JSON.stringify(f.encryptedMetadata).slice(0, 60) }}…</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty"><div class="icon">🗄</div>暂无文件记录</div>
  </div>
</template>
