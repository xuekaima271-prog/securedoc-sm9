/* 展示格式化工具（纯函数，无依赖） */

/** 字节数 → 人类可读（B/KB/MB/GB） */
export function fmtSize(n) {
  if (n == null || isNaN(n)) return '-';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/** ISO 时间 → 本地 "MM-DD HH:mm" */
export function fmtTime(t) {
  if (!t) return '-';
  const d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  const p = (x) => String(x).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/** ISO 时间 → 本地 "YYYY-MM-DD HH:mm:ss"（审计/安全事件等需按时间定责的页面用） */
export function fmtTimeFull(t) {
  if (!t) return '-';
  const d = new Date(t);
  if (isNaN(d.getTime())) return String(t);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 角色码 → 中文名 */
const ROLE_NAMES = { EMPLOYEE: '员工', SYS_ADMIN: '系统管理员', SUPER_ADMIN: '超级管理员', SECURITY_AUDITOR: '安全审计员', DEPT_ADMIN: '部门管理员', KGC_ADMIN: 'KGC管理员' };
export function roleName(code) { return ROLE_NAMES[code] || code; }
