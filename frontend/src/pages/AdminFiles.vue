<script setup>
import { ref, onMounted } from 'vue';
import { adminApi } from '../api/index.js';
import Icon from '../components/Icon.vue';

const items = ref([]);
const loaded = ref(false);
const msg = ref('');

async function load() {
  try { items.value = await adminApi.files(); }
  catch (e) { msg.value = e.message; }
  finally { loaded.value = true; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>密文记录（管理员视角）</h2>
    <p class="sub">管理员可审计全部文件密文记录，但<strong>看不到明文</strong>：元数据是 SM4 密文、密钥是 SM9 信封——服务端与管理员都无法解密，这正是端到端加密的证明。</p>
    <div class="msg err" v-if="msg">{{ msg }} <button class="link" @click="load"><Icon name="refresh" />重试</button></div>
    <div class="table-wrap" v-if="items.length">
      <table class="wide">
        <thead><tr><th>编号</th><th>发送人ID</th><th>状态</th><th class="num">分块</th><th class="num">接收人数</th><th>密文元数据（不可解）</th></tr></thead>
        <tbody>
          <tr v-for="f in items" :key="f.fileId">
            <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
            <td>{{ f.senderId }}</td>
            <td><span class="tag" :class="{ green: f.status === 'AVAILABLE' }">{{ f.status === 'AVAILABLE' ? '已投递' : f.status }}</span></td>
            <td class="num">{{ f.chunkCount }}</td>
            <td class="num">{{ f.recipientCount }}</td>
            <td class="mono cell-clip" :title="JSON.stringify(f.encryptedMetadata)">{{ JSON.stringify(f.encryptedMetadata).slice(0, 60) }}…</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="!loaded" class="loading">
      <div class="load-note">正在加载密文记录…</div>
      <div class="skel"><div class="skel-row"></div><div class="skel-row w70"></div><div class="skel-row w45"></div></div>
    </div>
    <div v-else-if="!msg" class="empty"><Icon name="database" class="empty-ic" /><div>暂无文件记录</div></div>
  </div>
</template>
