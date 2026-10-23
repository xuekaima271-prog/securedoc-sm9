import { http } from './http.js';

export const authApi = {
  login: (username, password) => http.post('/api/auth/login', { username, password }),
  me: () => http.get('/api/auth/me'),
  logout: () => http.post('/api/auth/logout'),
  changePassword: (oldPassword, newPassword) => http.post('/api/auth/change-password', { oldPassword, newPassword }),
};

export const keysApi = {
  myStatus: () => http.get('/api/keys/me/status'),
  masterPublicKey: () => http.get('/api/keys/master-public-key'),
  recipients: () => http.get('/api/keys/recipients'),
  init: (deviceFingerprint, password) => http.post('/api/keys/init', { deviceFingerprint, password }),
};

export const filesApi = {
  initUpload: (body) => http.post('/api/files/init-upload', body),
  uploadChunk: (fileId, index, bytes, digestB64, ivB64) =>
    http.put(`/api/files/${fileId}/chunks/${index}`, new Uint8Array(bytes), {
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Digest': digestB64, 'X-Chunk-IV': ivB64 },
    }),
  complete: (fileId) => http.post(`/api/files/${fileId}/complete`),
  inbox: () => http.get('/api/files/inbox'),
  outbox: () => http.get('/api/files/outbox'),
  keyEnvelope: (fileId) => http.get(`/api/files/${fileId}/recipients/me/key-envelope`),
  // 下载返回原始二进制 + 校验头（不走统一 JSON 解包）
  downloadChunk: async (fileId, index) => {
    const res = await fetch(`/api/files/${fileId}/chunks/${index}/download`, { credentials: 'include' });
    if (!res.ok) throw new Error(`下载分块失败(HTTP ${res.status})`);
    const buf = new Uint8Array(await res.arrayBuffer());
    return { bytes: [...buf], digestB64: res.headers.get('X-Chunk-Digest'), ivB64: res.headers.get('X-Chunk-IV') };
  },
};

export const adminApi = {
  files: () => http.get('/api/admin/files'),
  listUsers: () => http.get('/api/admin/users'),
  createUser: (payload) => http.post('/api/admin/users', payload),
  updateUserStatus: (id, status) => http.put(`/api/admin/users/${id}/status`, { status }),
  updateUserRoles: (id, roleCodes) => http.put(`/api/admin/users/${id}/roles`, { roleCodes }),
};

export const auditApi = {
  logs: ({ page = 1, size = 20, action = '' } = {}) =>
    http.get(`/api/audit/logs?page=${page}&size=${size}${action ? `&action=${encodeURIComponent(action)}` : ''}`),
  verify: () => http.get('/api/audit/verify'),
  kgcIssues: ({ page = 1, size = 20 } = {}) => http.get(`/api/admin/kgc-issues?page=${page}&size=${size}`),
  securityEvents: ({ page = 1, size = 20, eventType = '', severity = '' } = {}) =>
    http.get(`/api/audit/security-events?page=${page}&size=${size}`
      + (eventType ? `&eventType=${encodeURIComponent(eventType)}` : '')
      + (severity ? `&severity=${encodeURIComponent(severity)}` : '')),
};
