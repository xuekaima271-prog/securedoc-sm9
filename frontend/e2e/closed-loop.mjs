/* =============================================================================
 * Step 6 E2E 闸门：前端真加密模块(secure-doc) ↔ 真后端(:8080，代理KGC) ↔ 真KGC(:8081)
 * 完整 Alice→Bob 端到端闭环：
 *   alice 登录 → 取主公钥 → sealFile(SM4分块加密 + SM9封装DEK给Bob) → init/上传/complete
 *   bob 登录 → /keys/init 取私钥包 → 收件箱 → 取信封 → SM9解封DEK → 下载分块(校验SM3) → SM4解密 → 还原明文/元数据
 * 强负例：carol 取Bob信封→403；carol私钥解Bob信封→失败；篡改密文分块→SM3失败
 *
 * 与浏览器共用 src/crypto/secure-doc.js 和静态 ESM 密码库。
 * ===========================================================================*/
import G from '../src/crypto/gmssl.js';
import { createSecureDoc } from '../src/crypto/secure-doc.js';
import { b64ToBytes, utf8ToBytes, bytesToUtf8 } from '../src/crypto/b64.js';

const BASE = process.env.APP_BASE || 'http://localhost:8080';

const sdoc = createSecureDoc(G);

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { c ? (pass++, console.log('  ✅', n)) : (fail++, console.log('  ❌', n)); if (e) console.log('     ', e); };

// ---- 极简 cookie jar 会话 ----
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
  };
}
async function login(s, username) {
  const r = await s.fetch('/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password: 'Demo@123' }),
  });
  return r.ok && (await r.json()).success;
}

(async () => {
  console.log('\n======== Step6 E2E：前端加密模块 ↔ 真后端 ↔ 真KGC 闭环 ========');
  console.log('  · APP =', BASE);

  const BOB = { userId: 10002, identity: 'user:corp001:10002:bob@example.com' };
  const plaintext = utf8ToBytes('这是发给 Bob 的机密合同正文。'.repeat(8) + ' END-OF-FILE');
  const metadata = { fileName: '机密合同.txt', mimeType: 'text/plain', remark: '发给Bob审阅', originalSize: plaintext.length };

  // ---------- 发送方 Alice ----------
  const alice = newSession();
  ok('alice 登录', await login(alice, 'alice'));

  const mpkRes = await (await alice.fetch('/api/keys/master-public-key')).json();
  const mpk = b64ToBytes(mpkRes.data.masterPublicKey);
  ok('取 SM9 主公钥(64B, 经后端代理KGC)', mpk.length === 64);

  // 真加密：SM4 分块 + SM9 封装 DEK（小 chunkSize 强制多块）
  const sealed = sdoc.sealFile({ fileBytes: plaintext, metadata, recipients: [BOB], masterPublicKeyBytes: mpk, chunkSize: 48 });
  ok('sealFile 多分块', sealed.chunkCount >= 2, 'chunkCount=' + sealed.chunkCount);

  const initBody = {
    encryptedMetadata: sealed.encryptedMetadata,
    chunkSize: sealed.chunkSize, chunkCount: sealed.chunkCount, totalSize: sealed.totalSize,
    recipients: sealed.recipients,
  };
  const initJson = await (await alice.fetch('/api/files/init-upload', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(initBody),
  })).json();
  const fileId = initJson.data?.fileId;
  ok('init-upload 返回 fileId', !!fileId, 'fileId=' + fileId);

  for (const c of sealed.chunks) {
    const r = await alice.fetch(`/api/files/${fileId}/chunks/${c.index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Digest': c.digestB64, 'X-Chunk-IV': c.ivB64 },
      body: new Uint8Array(c.ciphertext),
    });
    if (!r.ok) { ok('上传分块 ' + c.index, false, await r.text()); }
  }
  const cmp = await (await alice.fetch(`/api/files/${fileId}/complete`, { method: 'POST' })).json();
  ok('complete → AVAILABLE', cmp.data?.status === 'AVAILABLE');

  // ---------- 接收方 Bob ----------
  const bob = newSession();
  ok('bob 登录', await login(bob, 'bob'));

  const bobInit = await (await bob.fetch('/api/keys/init', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceFingerprint: 'e2e-bob', password: 'Demo@123' }),
  })).json();
  const bobDe = b64ToBytes(bobInit.data.privateKeyPackage);
  ok('bob /keys/init 取私钥包(128B, 经后端代理KGC)', bobDe.length === 128);

  const inbox = (await (await bob.fetch('/api/files/inbox')).json()).data;
  const entry = inbox.find((f) => f.fileId === fileId);
  ok('bob 收件箱含该文件', !!entry);

  const envJson = (await (await bob.fetch(`/api/files/${fileId}/recipients/me/key-envelope`)).json()).data;
  ok('bob 取到密钥信封', !!envJson?.keyEnvelope?.wrappedKey);

  const dek = sdoc.unwrapDek({ keyEnvelope: envJson.keyEnvelope, identity: BOB.identity, privateKeyBytes: bobDe });
  ok('bob SM9 解封 DEK 成功(含DEK摘要校验)', Array.isArray(dek) && dek.length === 16);

  // 下载每块 + 校验 SM3 + SM4 解密
  const recovered = [];
  let firstCipher = null, firstIv = null, firstDigest = null;
  for (let i = 0; i < entry.chunkCount; i++) {
    const r = await bob.fetch(`/api/files/${fileId}/chunks/${i}/download`);
    const buf = [...new Uint8Array(await r.arrayBuffer())];
    const digest = r.headers.get('X-Chunk-Digest');
    const iv = r.headers.get('X-Chunk-IV');
    if (i === 0) { firstCipher = buf; firstIv = iv; firstDigest = digest; }
    const plain = sdoc.openChunk({ dek, ivB64: iv, ciphertext: buf, expectDigestB64: digest });
    recovered.push(...plain);
  }
  ok('下载全部分块 + SM3 校验 + SM4 解密 → 明文逐字节还原',
    recovered.length === plaintext.length && recovered.every((b, i) => b === plaintext[i]));

  const meta = sdoc.openMetadata({ dek, encryptedMetadata: entry.encryptedMetadata });
  ok('解密元数据 → 文件名还原', meta.fileName === '机密合同.txt', 'fileName=' + meta.fileName);

  // ---------- 强负例 ----------
  // 1) 篡改密文分块 → SM3 校验失败
  let tamperFail = false;
  try { const t = firstCipher.slice(); t[0] ^= 0x01; sdoc.openChunk({ dek, ivB64: firstIv, ciphertext: t, expectDigestB64: firstDigest }); }
  catch { tamperFail = true; }
  ok('篡改密文分块 → SM3 校验失败(拒绝)', tamperFail);

  // 2) carol（非接收人）取信封 → 403
  const carol = newSession();
  await login(carol, 'carol');
  const carolEnv = await carol.fetch(`/api/files/${fileId}/recipients/me/key-envelope`);
  ok('carol 取 Bob 信封 → 403', carolEnv.status === 403);

  // 3) carol 私钥解 Bob 信封 → SM9 失败（身份绑定）
  const carolInit = await (await carol.fetch('/api/keys/init', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceFingerprint: 'e2e-carol', password: 'Demo@123' }),
  })).json();
  const carolDe = b64ToBytes(carolInit.data.privateKeyPackage);
  let wrongKeyFail = false;
  try { sdoc.unwrapDek({ keyEnvelope: envJson.keyEnvelope, identity: BOB.identity, privateKeyBytes: carolDe }); }
  catch { wrongKeyFail = true; }
  ok('carol 私钥解 Bob 信封 → 失败(SM9 身份绑定)', wrongKeyFail);

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('运行异常:', e); process.exit(1); });
