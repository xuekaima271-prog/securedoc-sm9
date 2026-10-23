<script setup>
import { ref, computed, onMounted } from 'vue';
import { auditApi } from '../api/index.js';
import { fmtTime } from '../utils/fmt.js';

const page = ref({ records: [], total: 0, page: 1, size: 20 });
const totalPages = computed(() => Math.max(1, Math.ceil(page.value.total / (page.value.size || 20))));
const eventType = ref('');
const severity = ref('');
const msg = ref('');

const TYPES = {
  BRUTE_FORCE_LOCK: '暴力破解锁定',
  IP_THROTTLED: 'IP 限流',
  ACCESS_DENIED: '越权访问',
  UNAUTHORIZED_FILE_ACCESS: '非接收人取件',
  CHUNK_TAMPER_DETECTED: '密文篡改检出',
  OVERSIZED_CHUNK: '超大分块上传',
  AUDIT_CHAIN_BROKEN: '审计链断裂',
};
const SEV = { HIGH: '高危', MEDIUM: '中危', LOW: '低危' };
const sevClass = (s) => (s === 'HIGH' ? 'red' : s === 'MEDIUM' ? '' : 'blue');

async function load(p = 1) {
  try { page.value = await auditApi.securityEvents({ page: p, size: 20, eventType: eventType.value, severity: severity.value }); }
  catch (e) { msg.value = e.message; }
}
onMounted(() => load(1));
</script>

<template>
  <div class="card fade-in">
    <h2>安全事件（§2.2.12）</h2>
    <p class="sub">由防线埋点自动生成：暴力破解 / 越权访问 / 非接收人取件 / 密文篡改 / 超大上传 / 审计链断裂。与审计日志互补：事件面向攻击面，审计面向操作面。</p>
    <div class="row">
      <select v-model="eventType" style="max-width:220px" @change="load(1)">
        <option value="">全部类型</option>
        <option v-for="(n, t) in TYPES" :key="t" :value="t">{{ n }}</option>
      </select>
      <select v-model="severity" style="max-width:140px" @change="load(1)">
        <option value="">全部级别</option>
        <option value="HIGH">高危</option>
        <option value="MEDIUM">中危</option>
        <option value="LOW">低危</option>
      </select>
      <button class="ghost" @click="load(1)">刷新</button>
    </div>
    <div class="msg err" v-if="msg">{{ msg }}</div>

    <table v-if="page.records && page.records.length">
      <thead><tr><th>时间</th><th>类型</th><th>级别</th><th>触发用户</th><th>来源IP</th><th>资源</th><th>详情</th></tr></thead>
      <tbody>
        <tr v-for="e in page.records" :key="e.id">
          <td>{{ fmtTime(e.createdAt) }}</td>
          <td>{{ TYPES[e.eventType] || e.eventType }}</td>
          <td><span class="tag" :class="sevClass(e.severity)">{{ SEV[e.severity] || e.severity }}</span></td>
          <td>{{ e.actorId ?? '未登录' }}</td>
          <td class="mono">{{ e.clientIp }}</td>
          <td class="mono">{{ e.resource }}</td>
          <td>{{ e.detail }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty"><div class="icon">🛡</div>暂无安全事件（系统安全态势良好）</div>
    <div class="row" style="margin-top:0.6rem;">
      <span class="mono">共 {{ page.total }} 条 · 第 {{ page.page }} / {{ totalPages }} 页</span>
      <button class="ghost" :disabled="page.page <= 1" @click="load(page.page - 1)">上一页</button>
      <button class="ghost" :disabled="page.page >= totalPages" @click="load(page.page + 1)">下一页</button>
    </div>
  </div>
</template>
