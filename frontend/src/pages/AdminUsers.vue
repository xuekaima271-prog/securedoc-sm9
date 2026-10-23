<script setup>
import { ref, reactive, onMounted } from 'vue';
import { adminApi } from '../api/index.js';
import { roleName } from '../utils/fmt.js';

function toggleIn(arr, v) { const i = arr.indexOf(v); i >= 0 ? arr.splice(i, 1) : arr.push(v); }

const users = ref([]);
const msg = ref('');
const msgType = ref('info');
const ALL_ROLES = ['EMPLOYEE', 'SYS_ADMIN', 'SECURITY_AUDITOR', 'DEPT_ADMIN', 'KGC_ADMIN'];

const showCreate = ref(false);
const creating = ref(false);
const form = reactive({ username: '', password: '', realName: '', email: '', roleCodes: ['EMPLOYEE'] });

async function load() {
  try { users.value = await adminApi.listUsers(); } catch (e) { fail(e); }
}
function ok(m) { msgType.value = 'ok'; msg.value = m; }
function fail(e) { msgType.value = 'err'; msg.value = e.message || '操作失败'; }

async function createUser() {
  creating.value = true;
  try {
    const u = await adminApi.createUser({ ...form, roleCodes: [...form.roleCodes] });
    ok(`已创建用户 ${u.username}（ID ${u.userId ?? u.id ?? ''}），SM9 身份已登记到 KGC，密钥状态 UNINITIALIZED（用户首次登录后自行初始化）`);
    showCreate.value = false;
    Object.assign(form, { username: '', password: '', realName: '', email: '', roleCodes: ['EMPLOYEE'] });
    await load();
  } catch (e) { fail(e); } finally { creating.value = false; }
}

async function toggle(u) {
  const next = u.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE';
  try { await adminApi.updateUserStatus(u.id, next); ok(`已将 ${u.username} 置为 ${next}`); await load(); }
  catch (e) { fail(e); }
}
async function saveRoles(u) {
  try { await adminApi.updateUserRoles(u.id, u._editRoles); ok(`已更新 ${u.username} 的角色`); await load(); }
  catch (e) { fail(e); }
}
function startEdit(u) { u._editRoles = [...(u.roles || [])]; u._editing = true; }

onMounted(load);
</script>

<template>
  <div class="card fade-in">
    <h2>用户管理（管理员）</h2>
    <p class="sub">新增用户、启用/禁用账号、调整角色。所有写操作进入审计哈希链，可在「审计」页验证完整性。</p>
    <div class="msg" :class="msgType" v-if="msg">{{ msg }}</div>

    <button class="ghost" @click="showCreate = !showCreate">{{ showCreate ? '收起' : '＋ 新增用户' }}</button>
    <form v-if="showCreate" @submit.prevent="createUser" style="border:1px solid #e5e7eb; border-radius:8px; padding:0.8rem 1rem; margin:0.8rem 0;">
      <div class="row">
        <div style="flex:1; min-width:160px;"><label>用户名</label><input v-model="form.username" required /></div>
        <div style="flex:1; min-width:160px;"><label>初始密码（≥8位）</label><input v-model="form.password" type="password" required minlength="8" /></div>
      </div>
      <div class="row">
        <div style="flex:1; min-width:160px;"><label>姓名</label><input v-model="form.realName" /></div>
        <div style="flex:1; min-width:160px;"><label>邮箱（构成 SM9 身份）</label><input v-model="form.email" type="email" required /></div>
      </div>
      <label>角色（点选，可多个）</label>
      <div class="row" style="gap:.4rem">
        <button v-for="r in ALL_ROLES" :key="r" type="button"
                :class="form.roleCodes.includes(r) ? '' : 'ghost'"
                style="font-size:.82rem; padding:.3rem .7rem"
                @click="toggleIn(form.roleCodes, r)">{{ roleName(r) }}</button>
      </div>
      <div style="margin-top:0.8rem;">
        <button type="submit" :disabled="creating">{{ creating ? '创建中…（登记 KGC）' : '创建用户' }}</button>
      </div>
    </form>
    <table v-if="users.length">
      <thead><tr><th>ID</th><th>用户名</th><th>姓名</th><th>状态</th><th>角色</th><th>密钥</th><th>操作</th></tr></thead>
      <tbody>
        <tr v-for="u in users" :key="u.id">
          <td>{{ u.id }}</td>
          <td>{{ u.username }}</td>
          <td>{{ u.realName }}</td>
          <td><span class="tag" :class="u.status === 'ACTIVE' ? 'green' : 'red'">{{ u.status === 'ACTIVE' ? '启用' : (u.status === 'DISABLED' ? '禁用' : u.status) }}</span></td>
          <td>
            <template v-if="!u._editing">{{ (u.roles || []).map(roleName).join('、') }}</template>
            <template v-else>
              <div class="row" style="gap:.3rem">
                <button v-for="r in ALL_ROLES" :key="r" type="button"
                        :class="u._editRoles.includes(r) ? '' : 'ghost'"
                        style="font-size:.76rem; padding:.22rem .55rem"
                        @click="toggleIn(u._editRoles, r)">{{ roleName(r) }}</button>
              </div>
            </template>
          </td>
          <td><span class="tag" :class="{ green: u.keyStatus && u.keyStatus !== 'UNINITIALIZED' }">{{ u.keyStatus || '—' }}</span></td>
          <td>
            <button class="ghost" @click="toggle(u)">{{ u.status === 'ACTIVE' ? '禁用' : '启用' }}</button>
            <template v-if="!u._editing">
              <button class="ghost" @click="startEdit(u)" style="margin-left: 0.4rem;">改角色</button>
            </template>
            <template v-else>
              <button @click="saveRoles(u)" style="margin-left: 0.4rem;">保存</button>
              <button class="link" @click="u._editing = false" style="margin-left: 0.4rem;">取消</button>
            </template>
          </td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
