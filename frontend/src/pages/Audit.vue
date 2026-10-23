<script setup>
import { ref, computed, onMounted } from 'vue';
import { auditApi } from '../api/index.js';
import { fmtTimeFull } from '../utils/fmt.js';
import Icon from '../components/Icon.vue';

const page = ref({ records: [], total: 0, page: 1, size: 20 });
const action = ref('');
const verifyResult = ref(null);
const msg = ref('');
const kgc = ref(null);   // KGC 签发记录分页
const loaded = ref(false);
const kgcLoading = ref(false);

const totalPages = computed(() => Math.max(1, Math.ceil(page.value.total / (page.value.size || 20))));
const kgcTotalPages = computed(() =>
  kgc.value ? Math.max(1, Math.ceil(kgc.value.total / (kgc.value.size || 20))) : 1);

async function load(p = 1) {
  try { page.value = await auditApi.logs({ page: p, size: 20, action: action.value }); }
  catch (e) { msg.value = e.message; }
  finally { loaded.value = true; }
}
async function verify() {
  try { verifyResult.value = await auditApi.verify(); }
  catch (e) { msg.value = e.message; }
}
async function loadKgc(p = 1) {
  kgcLoading.value = true;
  try { kgc.value = await auditApi.kgcIssues({ page: p, size: 20 }); }
  catch (e) { msg.value = e.message + '（KGC 是否在运行？）'; }
  finally { kgcLoading.value = false; }
}
onMounted(() => load(1));
</script>

<template>
  <div class="card fade-in">
    <h2>审计日志（审计员 / 管理员）</h2>
    <p class="sub">每条日志以 SM3 哈希链入库（current = SM3(previous‖内容)），任何篡改/删除/重排均可被一键检出。</p>
    <div class="row">
      <input v-model="action" placeholder="按动作过滤，如 LOGIN / FILE_UPLOAD / USER_STATUS" style="max-width: 380px;" />
      <button @click="load(1)">查询</button>
      <button class="ghost" @click="verify">验证哈希链完整性</button>
    </div>
    <div class="msg err" v-if="msg">{{ msg }}</div>
    <div v-if="verifyResult" class="msg" :class="verifyResult.valid ? 'ok' : 'err'">
      {{ verifyResult.message }}
      <span v-if="!verifyResult.valid">（断裂记录 id={{ verifyResult.brokenAtId }}）</span>
    </div>

    <div class="table-wrap" v-if="page.records && page.records.length">
      <table class="wide">
        <thead><tr><th>ID</th><th>时间</th><th>动作</th><th>操作人</th><th>资源</th><th>IP</th><th>详情</th></tr></thead>
        <tbody>
          <tr v-for="a in page.records" :key="a.id">
            <td class="mono">{{ a.id }}</td>
            <td class="mono">{{ fmtTimeFull(a.createdAt) }}</td>
            <td><span class="tag">{{ a.action }}</span></td>
            <td>{{ a.actorId ?? '系统' }}</td>
            <td class="mono">{{ a.resourceType }}{{ a.resourceId ? ('/' + a.resourceId) : '' }}</td>
            <td class="mono">{{ a.clientIp }}</td>
            <td class="cell-clip" :title="a.detail || ''">{{ a.detail }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="!loaded" class="loading">
      <div class="load-note">正在加载审计日志…</div>
      <div class="skel"><div class="skel-row"></div><div class="skel-row w70"></div><div class="skel-row w45"></div></div>
    </div>
    <div v-else-if="!msg" class="empty"><Icon name="audit" class="empty-ic" /><div>暂无审计记录</div></div>
    <div class="row mt-2">
      <span class="mono">共 {{ page.total }} 条 · 第 {{ page.page }} / {{ totalPages }} 页</span>
      <button class="ghost" :disabled="page.page <= 1" @click="load(page.page - 1)">上一页</button>
      <button class="ghost" :disabled="page.page >= totalPages" @click="load(page.page + 1)">下一页</button>
    </div>

    <hr class="divider" />
    <h3>KGC 私钥签发记录 <button class="ghost btn-sm" @click="loadKgc(1)" style="margin-left:0.6rem;">加载</button></h3>
    <p class="sub">来自 KGC 独立审计（kgc_private_key_issues），经服务端令牌代理查询；issueType 区分首次(FIRST)/换设备重签发(REISSUE)。</p>
    <div class="table-wrap" v-if="kgc && kgc.records && kgc.records.length">
      <table class="wide">
        <thead><tr><th>issueId</th><th>用户</th><th>SM9 身份</th><th>类型</th><th>状态</th><th>时间</th></tr></thead>
        <tbody>
          <tr v-for="r in kgc.records" :key="r.id">
            <td class="mono">{{ String(r.id).slice(0, 8) }}…</td>
            <td>{{ r.userId }}</td>
            <td class="mono">{{ r.sm9Identity }}</td>
            <td><span class="tag" :class="r.issueType === 'FIRST' ? 'green' : 'blue'">{{ r.issueType === 'FIRST' ? '首次签发' : '重签发' }}</span></td>
            <td>{{ r.auditStatus }}</td>
            <td class="mono">{{ fmtTimeFull(r.issuedAt) }}</td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else-if="kgcLoading" class="loading">
      <div class="load-note">正在加载签发记录…</div>
      <div class="skel"><div class="skel-row"></div><div class="skel-row w70"></div></div>
    </div>
    <div v-else-if="kgc && !msg" class="empty"><Icon name="key" class="empty-ic" /><div>暂无签发记录</div></div>
    <div class="row mt-2" v-if="kgc">
      <span class="mono">共 {{ kgc.total }} 条 · 第 {{ kgc.page }} / {{ kgcTotalPages }} 页</span>
      <button class="ghost" :disabled="kgc.page <= 1" @click="loadKgc(kgc.page - 1)">上一页</button>
      <button class="ghost" :disabled="kgc.page >= kgcTotalPages" @click="loadKgc(kgc.page + 1)">下一页</button>
    </div>
  </div>
</template>
