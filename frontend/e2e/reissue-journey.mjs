/* =============================================================================
 * 换设备重签发旅程（§2.4 / §2873）：
 *   bob 首次 init(或已初始化) → 再次 init(换设备) → backend 走 KGC /reissue-private-key
 *   → KGC 审计 issue_type=REISSUE → 新私钥可解新文件 → 管理员在 /api/admin/kgc-issues 看到 REISSUE
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

(async () => {
  console.log('\n======== 换设备重签发旅程 ========');
  const BOB = { userId: 10002, identity: 'user:corp001:10002:bob@example.com' };

  const bob = newSession(); ok('bob 登录', await login(bob, 'bob'));

  // 第一次 init（保证已初始化状态）
  const init1 = await bob.json('/api/keys/init', { deviceFingerprint: 'device-A', password: 'Demo@123' });
  ok('第一次 init 成功', init1.success);
  const st1 = (await bob.json('/api/keys/me/status', undefined, 'GET')).data;

  // 第二次 init = 换设备重签发
  const init2 = await bob.json('/api/keys/init', { deviceFingerprint: 'device-B-new', password: 'Demo@123' });
  ok('第二次 init(换设备) 成功', init2.success, `issueId=${init2.data?.issueId}`);
  const de2 = b64ToBytes(init2.data.privateKeyPackage);
  ok('新私钥包 128B', de2.length === 128);
  // SM9 私钥由身份确定性导出（同一主密钥+同一身份 → 同一私钥），换设备重取应一致
  ok('重签发私钥与首次一致(确定性提取)', init2.data.privateKeyPackage === init1.data.privateKeyPackage);

  const st2 = (await bob.json('/api/keys/me/status', undefined, 'GET')).data;
  ok('backend 状态推进为 REISSUED', st2.keyStatus === 'REISSUED', `之前=${st1.keyStatus}`);

  // 管理员查 KGC 签发记录：bob 应有 REISSUE 记录（本次 issueId 且 issueType=REISSUE）
  const admin = newSession(); await login(admin, 'admin');
  const issues = await admin.json('/api/admin/kgc-issues?page=1&size=50&userId=10002', undefined, 'GET');
  const recs = issues.data?.records || [];
  const mine = recs.find((r) => r.id === init2.data.issueId);
  ok('KGC 签发记录含本次 issueId 且 issueType=REISSUE(两侧审计一致)',
    !!mine && mine.issueType === 'REISSUE', `records=${recs.length}`);

  // 新私钥解新文件（重签发后功能完好）
  const alice = newSession(); await login(alice, 'alice');
  const mpk = b64ToBytes((await alice.json('/api/keys/master-public-key', undefined, 'GET')).data.masterPublicKey);
  const plaintext = utf8ToBytes('重签发后 Bob 用新设备私钥解密这份文件。');
  const sealed = sdoc.sealFile({
    fileBytes: plaintext, metadata: { fileName: '重签发验证.txt', mimeType: 'text/plain', originalSize: plaintext.length },
    recipients: [BOB], masterPublicKeyBytes: mpk, chunkSize: 64,
  });
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
  await alice.json(`/api/files/${fileId}/complete`);
  const env = (await bob.json(`/api/files/${fileId}/recipients/me/key-envelope`, undefined, 'GET')).data;
  const dek = sdoc.unwrapDek({ keyEnvelope: env.keyEnvelope, identity: BOB.identity, privateKeyBytes: de2 });
  const entry = (await bob.json('/api/files/inbox', undefined, 'GET')).data.find((f) => f.fileId === fileId);
  const rec = [];
  for (let i = 0; i < entry.chunkCount; i++) {
    const r = await bob.fetch(`/api/files/${fileId}/chunks/${i}/download`);
    const buf = [...new Uint8Array(await r.arrayBuffer())];
    rec.push(...sdoc.openChunk({ dek, ivB64: r.headers.get('X-Chunk-IV'), ciphertext: buf, expectDigestB64: r.headers.get('X-Chunk-Digest') }));
  }
  ok('重签发后的私钥解新文件 → 明文还原', rec.length === plaintext.length && rec.every((b, i) => b === plaintext[i]));

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('运行异常:', e); process.exit(1); });
