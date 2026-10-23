/* =============================================================================
 * 新用户完整旅程 E2E（Step9 批次）：管理员创建 → 新用户登录 → KGC 签发 → 收加密文件 → 解密还原
 *
 *   1. admin 创建新用户 dave_{ts}（后端建三表 + 生成 SM9 身份 + 登记到真 KGC）
 *   2. dave 登录成功（BCrypt 初始密码）
 *   3. dave /keys/me/status = UNINITIALIZED → /keys/init → 真 KGC 签发 128B 私钥包（证明登记生效）
 *   4. dave 出现在 alice 的可选接收人列表（含正确身份）
 *   5. alice 真加密发文件给 dave → dave 信封解封 DEK → 下载校验 SM3 → SM4 解密逐字节还原
 *   负例：重名创建 400；员工创建 403
 * ===========================================================================*/
import G from '../src/crypto/gmssl.js';
import { createSecureDoc } from '../src/crypto/secure-doc.js';
import { b64ToBytes, utf8ToBytes } from '../src/crypto/b64.js';

const BASE = process.env.APP_BASE || 'http://localhost:8080';
const sdoc = createSecureDoc(G);

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { c ? (pass++, console.log('  ✅', n)) : (fail++, console.log('  ❌', n)); if (e) console.log('     ', e); };

function newSession() {
  let cookie = '';
  return {
    async fetch(path, opts = {}) {
      const headers = { ...(opts.headers || {}) };
      if (cookie) headers['Cookie'] = cookie;
      const res = await fetch(BASE + path, { ...opts, headers });
      const sc = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
      for (const c of sc) { const m = c.match(/JSESSIONID=[^;]+/); if (m) cookie = m[0]; }
      return res;
    },
    json(path, body, method = 'POST') {
      return this.fetch(path, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      }).then((r) => r.json().then((j) => ({ status: r.status, ...j })));
    },
  };
}
const login = async (s, u, p = 'Demo@123') =>
  (await s.json('/api/auth/login', { username: u, password: p })).success;

(async () => {
  console.log('\n======== 新用户完整旅程：创建→登录→KGC签发→收文件→解密 ========');
  const ts = Date.now() % 1000000;
  const uname = `dave${ts}`;
  const email = `dave${ts}@example.com`;
  const pwd = 'Dave@12345';

  // ---- 1. admin 创建新用户 ----
  const admin = newSession();
  ok('admin 登录', await login(admin, 'admin'));
  const created = await admin.json('/api/admin/users',
    { username: uname, password: pwd, realName: '新员工戴夫', email, roleCodes: ['EMPLOYEE'] });
  ok('admin 创建新用户(真 KGC 登记)', created.success, `id=${created.data?.id} 状态=${created.data?.keyStatus}`);
  const daveId = created.data.id;

  // 负例：重名 400 / 员工 403
  const dup = await admin.json('/api/admin/users',
    { username: uname, password: pwd, email: 'x' + email, roleCodes: ['EMPLOYEE'] });
  ok('重名创建 → 400', dup.status === 400);

  // ---- 2. dave 登录 ----
  const dave = newSession();
  ok('新用户 dave 登录成功', await login(dave, uname, pwd));

  const empTry = await dave.json('/api/admin/users',
    { username: 'x' + uname, password: pwd, email: 'y' + email, roleCodes: ['EMPLOYEE'] });
  ok('员工创建用户 → 403', empTry.status === 403);

  // ---- 3. 密钥初始化（真 KGC 签发，证明登记生效）----
  const st = await dave.json('/api/keys/me/status', undefined, 'GET');
  ok('dave 初始密钥状态 UNINITIALIZED', st.data?.keyStatus === 'UNINITIALIZED', `identity=${st.data?.identity}`);
  const expectedIdentity = `user:corp001:${daveId}:${email}`;
  ok('身份格式 user:corp001:{id}:{email}', st.data?.identity === expectedIdentity);

  const init = await dave.json('/api/keys/init', { deviceFingerprint: 'e2e-journey', password: pwd });
  ok('dave /keys/init → 真 KGC 签发私钥包', init.success, `issueId=${init.data?.issueId}`);
  const daveDe = b64ToBytes(init.data.privateKeyPackage);
  ok('私钥包 128 字节', daveDe.length === 128);

  const st2 = await dave.json('/api/keys/me/status', undefined, 'GET');
  ok('签发后状态 ISSUED', st2.data?.keyStatus === 'ISSUED');

  // ---- 4. alice 的接收人列表含 dave ----
  const alice = newSession();
  ok('alice 登录', await login(alice, 'alice'));
  const recips = await alice.json('/api/keys/recipients', undefined, 'GET');
  const daveRec = (recips.data || []).find((r) => r.userId === daveId);
  ok('alice 可选接收人含 dave(正确身份)', !!daveRec && daveRec.identity === expectedIdentity);

  // ---- 5. alice 真加密发文件给 dave → dave 解密 ----
  const mpk = b64ToBytes((await alice.json('/api/keys/master-public-key', undefined, 'GET')).data.masterPublicKey);
  const plaintext = utf8ToBytes('欢迎新员工！这是发给 ' + uname + ' 的第一份加密文件。'.repeat(5));
  const sealed = sdoc.sealFile({
    fileBytes: plaintext,
    metadata: { fileName: '入职欢迎.txt', mimeType: 'text/plain', originalSize: plaintext.length },
    recipients: [{ userId: daveId, identity: expectedIdentity }],
    masterPublicKeyBytes: mpk, chunkSize: 64,
  });
  const initUp = await alice.json('/api/files/init-upload', {
    encryptedMetadata: sealed.encryptedMetadata,
    chunkSize: sealed.chunkSize, chunkCount: sealed.chunkCount, totalSize: sealed.totalSize,
    recipients: sealed.recipients,
  });
  const fileId = initUp.data.fileId;
  for (const c of sealed.chunks) {
    await alice.fetch(`/api/files/${fileId}/chunks/${c.index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Digest': c.digestB64, 'X-Chunk-IV': c.ivB64 },
      body: new Uint8Array(c.ciphertext),
    });
  }
  const cmp = await alice.json(`/api/files/${fileId}/complete`);
  ok('alice 发送文件给 dave → AVAILABLE', cmp.data?.status === 'AVAILABLE', `chunks=${sealed.chunkCount}`);

  const inbox = await dave.json('/api/files/inbox', undefined, 'GET');
  const entry = (inbox.data || []).find((f) => f.fileId === fileId);
  ok('dave 收件箱含该文件', !!entry);

  const env = await dave.json(`/api/files/${fileId}/recipients/me/key-envelope`, undefined, 'GET');
  const dek = sdoc.unwrapDek({ keyEnvelope: env.data.keyEnvelope, identity: expectedIdentity, privateKeyBytes: daveDe });
  ok('dave SM9 解封 DEK', dek.length === 16);

  const recovered = [];
  for (let i = 0; i < entry.chunkCount; i++) {
    const r = await dave.fetch(`/api/files/${fileId}/chunks/${i}/download`);
    const buf = [...new Uint8Array(await r.arrayBuffer())];
    recovered.push(...sdoc.openChunk({
      dek, ivB64: r.headers.get('X-Chunk-IV'), ciphertext: buf, expectDigestB64: r.headers.get('X-Chunk-Digest'),
    }));
  }
  ok('dave 下载+SM3校验+SM4解密 → 明文逐字节还原',
    recovered.length === plaintext.length && recovered.every((b, i) => b === plaintext[i]));
  const meta = sdoc.openMetadata({ dek, encryptedMetadata: entry.encryptedMetadata });
  ok('元数据还原 文件名=入职欢迎.txt', meta.fileName === '入职欢迎.txt');

  // ---- 审计链仍完整 ----
  const auditor = newSession();
  await login(auditor, 'auditor');
  const v = await auditor.json('/api/audit/verify', undefined, 'GET');
  ok('审计 SM3 哈希链验证 valid(含本旅程全部写操作)', v.data?.valid === true, v.data?.message);

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('运行异常:', e); process.exit(1); });
