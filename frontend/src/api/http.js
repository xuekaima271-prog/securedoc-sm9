// 统一 fetch 封装。credentials:'include' 携带 JSESSIONID Cookie；解包 {success,code,message,data}。

// 会话过期（401）全局处理：清会话状态并回登录页（带 redirect 回跳，与 router 守卫约定一致）。
// 登录与会话自举接口除外：登录失败的 401 是业务错误、自举 401 由路由守卫统一处理，避免重复跳转。
// 改密接口同理除外：旧密码输错返回 401 INVALID_CREDENTIALS，是业务错误而非会话过期，误跳会打断改密流程。
const AUTH_BOOTSTRAP_PATHS = ['/api/auth/login', '/api/auth/me', '/api/auth/change-password'];
let redirecting = false;   // 并发 401 只跳一次
async function onSessionExpired(path) {
  if (AUTH_BOOTSTRAP_PATHS.some((p) => path.startsWith(p))) return;
  if (redirecting) return;
  redirecting = true;
  try {
    // 动态导入避免 http ← api/index ← session/router 的静态循环依赖
    const [{ clearUser }, { default: router }] = await Promise.all([
      import('../store/session.js'),
      import('../router.js'),
    ]);
    clearUser();
    const cur = router.currentRoute.value;
    if (cur.path !== '/login') {
      await router.push({ path: '/login', query: { redirect: cur.fullPath } });
    }
  } catch { /* 跳转失败不掩盖原始 401 错误 */ } finally {
    redirecting = false;
  }
}

async function request(method, path, { body, headers } = {}) {
  const opts = { method, credentials: 'include', headers: { ...(headers || {}) } };
  if (body !== undefined && body !== null) {
    if (body instanceof Uint8Array) {
      opts.body = body;   // 二进制分块（Content-Type 由调用方设 octet-stream）
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
  }
  const res = await fetch(path, opts);
  let json;
  try { json = await res.json(); } catch { json = { success: false, code: 'PARSE_ERROR', message: '响应解析失败' }; }
  if (!res.ok || !json.success) {
    const err = new Error(json.message || `请求失败(HTTP ${res.status})`);
    err.code = json.code;
    err.status = res.status;
    if (res.status === 401) await onSessionExpired(path);
    throw err;
  }
  return json.data;
}

export const http = {
  get: (p, o) => request('GET', p, o),
  post: (p, b, o) => request('POST', p, { ...(o || {}), body: b }),
  put: (p, b, o) => request('PUT', p, { ...(o || {}), body: b }),
};
