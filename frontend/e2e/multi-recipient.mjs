/* =============================================================================
 * 多人接收 E2E（设计文档核心特性 §"多人接收时，文件密文只保存一份，
 * 但为每个接收人生成独立密钥信封"）：
 *   alice → bob + carol 发同一文件：
 *     · 密文分块只有一份（inbox 双方 chunkCount/totalSize 一致，对象键相同）
 *     · bob/carol 各自的信封 wrappedKey 不同（独立 SM9 封装）
 *     · bob 与 carol 各自用自己的私钥解封 → 解出同一 DEK → 各自完整还原明文
 *   强负例：
 *     · bob 的私钥解 carol 的信封 → 失败（信封身份绑定）
 *     · 双方信封 wrappedKey 逐字节不同
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
const login = async (s, u) => (await s.json('/api/auth/login', { username: u, password: 'Demo@123' })).success;

async function recoverAll(sess, fileId, chunkCount, dek) {
  const out = [];
  for (let i = 0; i < chunkCount; i++) {
    const r = await sess.fetch(`/api/files/${fileId}/chunks/${i}/download`);
    const buf = [...new Uint8Array(await r.arrayBuffer())];
    out.push(...sdoc.openChunk({
      dek, ivB64: r.headers.get('X-Chunk-IV'), ciphertext: buf, expectDigestB64: r.headers.get('X-Chunk-Digest'),
    }));
  }
  return out;
}

(async () => {
  console.log('\n======== 多人接收：一份密文 · 双信封 · 各自解密 ========');
  const BOB = { userId: 10002, identity: 'user:corp001:10002:bob@example.com' };
  const CAROL = { userId: 10003, identity: 'user:corp001:10003:carol@example.com' };

  // 准备双方私钥（经 /keys/init 从真 KGC 取）
  const bob = newSession(); ok('bob 登录', await login(bob, 'bob'));
  const carol = newSession(); ok('carol 登录', await login(carol, 'carol'));
  const bobDe = b64ToBytes((await bob.json('/api/keys/init', { deviceFingerprint: 'mr-bob', password: 'Demo@123' })).data.privateKeyPackage);
  const carolDe = b64ToBytes((await carol.json('/api/keys/init', { deviceFingerprint: 'mr-carol', password: 'Demo@123' })).data.privateKeyPackage);
  ok('bob/carol 私钥各 128B 且不同', bobDe.length === 128 && carolDe.length === 128
    && bobDe.join(',') !== carolDe.join(','));

  // alice 加密发给两人
  const alice = newSession(); ok('alice 登录', await login(alice, 'alice'));
  const mpk = b64ToBytes((await alice.json('/api/keys/master-public-key', undefined, 'GET')).data.masterPublicKey);
  const plaintext = utf8ToBytes('这份文件同时发给 Bob 与 Carol，密文只存一份，信封各一个。'.repeat(6));
  const sealed = sdoc.sealFile({
    fileBytes: plaintext,
    metadata: { fileName: '多人接收演示.txt', mimeType: 'text/plain', originalSize: plaintext.length },
    recipients: [BOB, CAROL], masterPublicKeyBytes: mpk, chunkSize: 96,
  });
  ok('sealFile 为两位接收人生成独立信封', sealed.recipients.length === 2);
  const [envB, envC] = sealed.recipients.map((r) => r.keyEnvelope.wrappedKey);
  ok('双信封 wrappedKey 不同(独立 SM9 封装)', envB !== envC);
  ok('双信封 keyDigest 相同(同一 DEK)', sealed.recipients[0].keyEnvelope.keyDigest === sealed.recipients[1].keyEnvelope.keyDigest);

  const init = await alice.json('/api/files/init-upload', {
    encryptedMetadata: sealed.encryptedMetadata,
    chunkSize: sealed.chunkSize, chunkCount: sealed.chunkCount, totalSize: sealed.totalSize,
    recipients: sealed.recipients,
  });
  const fileId = init.data.fileId;
  for (const c of sealed.chunks) {
    await alice.fetch(`/api/files/${fileId}/chunks/${c.index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Digest': c.digestB64, 'X-Chunk-IV': c.ivB64 },
      body: new Uint8Array(c.ciphertext),
    });
  }
  const cmp = await alice.json(`/api/files/${fileId}/complete`);
  ok('上传完成 AVAILABLE(密文仅一份)', cmp.data?.status === 'AVAILABLE', `chunks=${sealed.chunkCount}`);

  // 双方各自可见、信封不同、各自解密
  const inbB = (await bob.json('/api/files/inbox', undefined, 'GET')).data.find((f) => f.fileId === fileId);
  const inbC = (await carol.json('/api/files/inbox', undefined, 'GET')).data.find((f) => f.fileId === fileId);
  ok('bob 与 carol 收件箱均见该文件(同一密文)', !!inbB && !!inbC
    && inbB.chunkCount === inbC.chunkCount && inbB.totalSize === inbC.totalSize);

  const envBobSrv = (await bob.json(`/api/files/${fileId}/recipients/me/key-envelope`, undefined, 'GET')).data;
  const envCarolSrv = (await carol.json(`/api/files/${fileId}/recipients/me/key-envelope`, undefined, 'GET')).data;
  ok('服务端返回各自的信封(身份正确)', envBobSrv.recipientIdentity === BOB.identity
    && envCarolSrv.recipientIdentity === CAROL.identity);

  const dekBob = sdoc.unwrapDek({ keyEnvelope: envBobSrv.keyEnvelope, identity: BOB.identity, privateKeyBytes: bobDe });
  const dekCarol = sdoc.unwrapDek({ keyEnvelope: envCarolSrv.keyEnvelope, identity: CAROL.identity, privateKeyBytes: carolDe });
  ok('双方解封得到同一 DEK', dekBob.join(',') === dekCarol.join(','));

  const recB = await recoverAll(bob, fileId, inbB.chunkCount, dekBob);
  const recC = await recoverAll(carol, fileId, inbC.chunkCount, dekCarol);
  ok('bob 完整还原明文', recB.length === plaintext.length && recB.every((b, i) => b === plaintext[i]));
  ok('carol 完整还原明文', recC.length === plaintext.length && recC.every((b, i) => b === plaintext[i]));

  // 强负例：bob 的私钥解 carol 的信封（身份串用 carol 的）→ 必须失败
  let crossFail = false;
  try { sdoc.unwrapDek({ keyEnvelope: envCarolSrv.keyEnvelope, identity: CAROL.identity, privateKeyBytes: bobDe }); }
  catch { crossFail = true; }
  ok('bob 私钥解 carol 信封 → 失败(信封身份绑定)', crossFail);

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('运行异常:', e); process.exit(1); });
