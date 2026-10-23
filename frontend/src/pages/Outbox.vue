<script setup>
import { ref, onMounted } from 'vue';
import { filesApi, keysApi } from '../api/index.js';
import { fmtSize, fmtTime } from '../utils/fmt.js';
import Icon from '../components/Icon.vue';

const items = ref([]);
const names = ref({});   // userId -> 显示名
const msg = ref('');
const loaded = ref(false);

// 接收人列：兼容后端返回的 recipientIds（数组）/ recipientId（单个）两种形状，
// 经接收人名单映射为显示名；接口未提供接收人字段时显示「—」。
function recipNames(f) {
  const ids = Array.isArray(f.recipientIds) ? f.recipientIds
    : (f.recipientId != null ? [f.recipientId] : []);
  if (!ids.length) return '—';
  return ids.map((id) => names.value[id] || `用户${id}`).join('、');
}

async function load() {
  try {
    const [outbox, users] = await Promise.all([filesApi.outbox(), keysApi.recipients()]);
    items.value = outbox;
    names.value = Object.fromEntries(users.map((u) => [u.userId, u.realName || u.username]));
  } catch (e) { msg.value = e.message; }
  finally { loaded.value = true; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>发件箱</h2>
    <p class="sub">你发起的密文投递记录（服务器侧仅保存密文与摘要）。</p>
    <div class="msg err" v-if="msg">{{ msg }} <button class="link" @click="load"><Icon name="refresh" />重试</button></div>
    <div class="table-wrap" v-if="items.length">
      <table>
        <thead><tr><th>接收人</th><th>状态</th><th class="num">密文大小</th><th class="num">分块</th><th>时间</th><th>编号</th></tr></thead>
        <tbody>
          <tr v-for="f in items" :key="f.fileId">
            <td>{{ recipNames(f) }}</td>
            <td><span class="tag" :class="{ green: f.status === 'AVAILABLE' }">{{ f.status === 'AVAILABLE' ? '已投递' : f.status }}</span></td>
            <td class="num">{{ fmtSize(f.totalSize) }}</td>
            <td class="num">{{ f.chunkCount }}</td>
            <td>{{ fmtTime(f.createdAt) }}</td>
            <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="!loaded" class="loading">
      <div class="load-note">正在加载发件箱…</div>
      <div class="skel"><div class="skel-row"></div><div class="skel-row w70"></div><div class="skel-row w45"></div></div>
    </div>
    <div v-else-if="!msg" class="empty"><Icon name="outbox" class="empty-ic" /><div>暂无发送记录</div></div>
  </div>
</template>
