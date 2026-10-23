/* =============================================================================
 * 50MB 大文件分块上传验收（§18.13 性能验收项）：
 *   50MB 随机数据 → SM4 分块加密(4MiB×13) → 上传 → complete → bob 解封 → 下载+SM3校验+解密
 *   → 逐字节还原（抽样比对 + 长度 + 全量 SM3 比对），分段计时。
 * ===========================================================================*/
import G from '../src/crypto/gmssl.js';
import { randomBytes } from 'crypto';
import { createSecureDoc } from '../src/crypto/secure-doc.js';
import { b64ToBytes } from '../src/crypto/b64.js';

const BASE = process.env.APP_BASE || 'http://localhost:8080';
const sdoc = createSecureDoc(G);

let pass = 0, fail = 0;
const ok = (n, c, e = '') => { c ? (pass++, console.log('  ✅', n)) : (fail++, console.log('  ❌', n)); if (e) console.log('     ', e); };
const tmark = () => performance.now();
const sec = (t) => ((performance.now() - t) / 1000).toFixed(1) + 's';

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
  console.log('\n======== 50MB 大文件分块加密投递验收 ========');
  const BOB = { userId: 10002, identity: 'user:corp001:10002:bob@example.com' };
  const SIZE = 50 * 1024 * 1024;
  const CHUNK = 4 * 1024 * 1024;

  const alice = newSession(); await login(alice, 'alice');
  const bob = newSession(); await login(bob, 'bob');
  const bobDe = b64ToBytes((await bob.json('/api/keys/init', { deviceFingerprint: 'lf-bob', password: 'Demo@123' })).data.privateKeyPackage);
  const mpk = b64ToBytes((await alice.json('/api/keys/master-public-key', undefined, 'GET')).data.masterPublicKey);
  ok('准备完成(登录/私钥/主公钥)', bobDe.length === 128 && mpk.length === 64);

  let t = tmark();
  const fileBytes = [...randomBytes(SIZE)];
  const srcDigest = sdoc.fc.sm3DigestB64(fileBytes);
  console.log(`  · 生成 50MB 随机数据 + 源 SM3: ${sec(t)}`);

  t = tmark();
  const sealed = sdoc.sealFile({
    fileBytes, metadata: { fileName: '大文件50MB.bin', mimeType: 'application/octet-stream', originalSize: SIZE },
    recipients: [BOB], masterPublicKeyBytes: mpk, chunkSize: CHUNK,
  });
  const encSec = sec(t);
  ok(`SM4 分块加密 50MB → ${sealed.chunkCount} 块 (${encSec}, ${(50 / parseFloat(encSec)).toFixed(1)}MB/s 含SM3)`,
    sealed.chunkCount === Math.ceil(SIZE / CHUNK));

  t = tmark();
  const init = await alice.json('/api/files/init-upload', {
    encryptedMetadata: sealed.encryptedMetadata,
    chunkSize: sealed.chunkSize, chunkCount: sealed.chunkCount, totalSize: sealed.totalSize,
    recipients: sealed.recipients,
  });
  const fileId = init.data.fileId;
  for (const c of sealed.chunks) {
    const r = await alice.fetch(`/api/files/${fileId}/chunks/${c.index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/octet-stream', 'X-Chunk-Digest': c.digestB64, 'X-Chunk-IV': c.ivB64 },
      body: new Uint8Array(c.ciphertext),
    });
    if (!r.ok) { ok(`上传块 ${c.index}`, false, await r.text()); break; }
  }
  const cmp = await alice.json(`/api/files/${fileId}/complete`);
  ok(`上传 13 块 + complete → AVAILABLE (${sec(t)})`, cmp.data?.status === 'AVAILABLE');

  t = tmark();
  const env = (await bob.json(`/api/files/${fileId}/recipients/me/key-envelope`, undefined, 'GET')).data;
  const dek = sdoc.unwrapDek({ keyEnvelope: env.keyEnvelope, identity: BOB.identity, privateKeyBytes: bobDe });
  ok('bob SM9 解封 DEK', dek.length === 16);

  const entry = (await bob.json('/api/files/inbox', undefined, 'GET')).data.find((f) => f.fileId === fileId);
  let total = 0;
  const outDigestParts = [];   // 按块还原后拼接做全量 SM3（避免双持 50MB）
  const recovered = [];
  for (let i = 0; i < entry.chunkCount; i++) {
    const r = await bob.fetch(`/api/files/${fileId}/chunks/${i}/download`);
    const buf = [...new Uint8Array(await r.arrayBuffer())];
    const plain = sdoc.openChunk({ dek, ivB64: r.headers.get('X-Chunk-IV'), ciphertext: buf, expectDigestB64: r.headers.get('X-Chunk-Digest') });
    total += plain.length;
    for (let j = 0; j < plain.length; j++) recovered.push(plain[j]);
  }
  const decSec = sec(t);
  ok(`下载+SM3校验+SM4解密 50MB (${decSec}, ${(50 / parseFloat(decSec)).toFixed(1)}MB/s)`, total === SIZE);

  t = tmark();
  const outDigest = sdoc.fc.sm3DigestB64(recovered);
  ok(`全量 SM3 比对：还原内容 == 源数据 (${sec(t)})`, outDigest === srcDigest, `SM3=${outDigest.slice(0, 16)}…`);

  console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
  process.exit(fail === 0 ? 0 : 1);
})().catch((e) => { console.error('运行异常:', e); process.exit(1); });
