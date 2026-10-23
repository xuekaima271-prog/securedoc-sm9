<script setup>
// 演示账号一键填充：仅由 Login.vue 在开发构建中动态加载，本文件不进生产包，演示口令不随成品发布。
const emit = defineEmits(['fill']);
const demos = [
  { u: 'alice', d: '员工' }, { u: 'bob', d: '员工' }, { u: 'carol', d: '员工' },
  { u: 'admin', d: '管理员' }, { u: 'auditor', d: '审计员' },
];
</script>

<template>
  <p class="demo-note">演示账号（密码 Demo@123）：</p>
  <div class="demo-accounts">
    <button v-for="d in demos" :key="d.u" @click="emit('fill', d.u, 'Demo@123')" :title="d.d">{{ d.u }} · {{ d.d }}</button>
  </div>
</template>
