<script setup>
import { ref, onMounted } from 'vue';
import { filesApi, keysApi } from '../api/index.js';
import { fmtSize, fmtTime } from '../utils/fmt.js';
import Icon from '../components/Icon.vue';

const items = ref([]);
const names = ref({});   // userId -> 显示名
const msg = ref('');
const loaded = ref(false);

async function load() {
  try {
    const [inbox, users] = await Promise.all([filesApi.inbox(), keysApi.recipients()]);
    items.value = inbox;
    names.value = Object.fromEntries(users.map((u) => [u.userId, u.realName || u.username]));
  } catch (e) { msg.value = e.message; }
  finally { loaded.value = true; }
}
onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>收件箱</h2>
    <p class="sub">发给你的加密文件。文件名等元数据也是密文，解密后才可见。</p>
    <div class="msg err" v-if="msg">{{ msg }} <button class="link" @click="load"><Icon name="refresh" />重试</button></div>
    <div class="table-wrap" v-if="items.length">
      <table>
        <thead><tr><th>发送人</th><th class="num">密文大小</th><th class="num">分块</th><th>时间</th><th>编号</th><th></th></tr></thead>
        <tbody>
          <tr v-for="f in items" :key="f.fileId">
            <td><span class="avatar" style="width:22px;height:22px;font-size:.7rem;margin-right:.4rem">{{ (names[f.senderId] || '?').slice(0,1) }}</span>{{ names[f.senderId] || `用户${f.senderId}` }}</td>
            <td class="num">{{ fmtSize(f.totalSize) }}</td>
            <td class="num">{{ f.chunkCount }}</td>
            <td>{{ fmtTime(f.createdAt) }}</td>
            <td class="mono">{{ f.fileId.slice(0, 8) }}…</td>
            <td><router-link :to="`/decrypt/${f.fileId}`"><button class="ghost btn-sm"><Icon name="unlock" />解密下载</button></router-link></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="!loaded" class="loading">
      <div class="load-note">正在加载收件箱…</div>
      <div class="skel"><div class="skel-row"></div><div class="skel-row w70"></div><div class="skel-row w45"></div></div>
    </div>
    <div v-else-if="!msg" class="empty"><Icon name="inbox" class="empty-ic" /><div>暂无收到的文件</div></div>
  </div>
</template>
