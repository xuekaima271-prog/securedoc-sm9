/* SM9-6 性能基准（Node 侧，与浏览器共用同一 crypto 模块；浏览器侧见 /selftest 页）。
 * 输出 IBE 封装/解封（冷 1 次 + 热 N 次统计）、SM4-CBC 与 SM3 的 1MB 吞吐。 */
import G from '../src/crypto/gmssl.js';
import { createSecureDoc } from '../src/crypto/secure-doc.js';
import { b64ToBytes, utf8ToBytes } from '../src/crypto/b64.js';

const sdoc = createSecureDoc(G);

const PPUB = b64ToBytes('NlD9vX1H3X/QcmydttHlw095LoK+6PF0uXulc4T6SW2VOzCB+aEfSwEyRJPeRW9fXqZ0TB1Rg0cQaVFduMLHgg==');
const DE = b64ToBytes('FFcwiKWQtZXAqdMnrc3K9Js4JKW4TaT9N+yf18LHKm4Hfa8HkUy/SAcGlF+GFuKc3ueHWy1aNhnop+z4PwJ0U7PCwghZUbru3xR3h6qUCKlaq/A1soBFy1zMBBaCg/moClViDZQm6LGPIpoj9sBtVLoTfFTdyTz2j/Fj0Qqp2fE=');
const ID = 'selftest:corp001:1:self@test.local';

const ppub = sdoc.ibe.ppubFromBytes(PPUB);
const de = sdoc.ibe.deFromBytes(DE);
const idb = sdoc.ibe.idToBytes(ID);
const stat = (t) => {
  const s = [...t].sort((a, b) => a - b);
  const avg = s.reduce((x, y) => x + y, 0) / s.length;
  return `min=${s[0].toFixed(1)}ms avg=${avg.toFixed(1)}ms max=${s[s.length - 1].toFixed(1)}ms`;
};

console.log('==== SM9-6 性能基准 (Node ' + process.version + ') ====');
const dek = sdoc.fc.genDek();

// 冷启动（进程内首次）
let t0 = performance.now();
let env = sdoc.ibe.ibeEncrypt(dek, idb, ppub);
console.log(`IBE 封装(冷/首次): ${(performance.now() - t0).toFixed(1)}ms`);
t0 = performance.now();
sdoc.ibe.ibeDecrypt(env, idb, de);
console.log(`IBE 解封(冷/首次): ${(performance.now() - t0).toFixed(1)}ms`);

// 热 N 次
const N = 10;
const encT = [], decT = [];
for (let i = 0; i < N; i++) {
  t0 = performance.now(); env = sdoc.ibe.ibeEncrypt(dek, idb, ppub); encT.push(performance.now() - t0);
  t0 = performance.now(); sdoc.ibe.ibeDecrypt(env, idb, de); decT.push(performance.now() - t0);
}
console.log(`IBE 封装(热×${N}): ${stat(encT)}`);
console.log(`IBE 解封(热×${N}): ${stat(decT)}`);

// 对称吞吐
const MB = 1 << 20;
const big = new Array(MB).fill(0x5a);
t0 = performance.now();
const ct = sdoc.fc.sm4CbcEncrypt(dek, sdoc.fc.genIv(), big);
let ms = performance.now() - t0;
console.log(`SM4-CBC 加密 1MB: ${ms.toFixed(0)}ms (${(1000 / ms).toFixed(2)} MB/s)`);
t0 = performance.now();
G.sm3(ct.slice(0, MB));
ms = performance.now() - t0;
console.log(`SM3 摘要 1MB   : ${ms.toFixed(0)}ms (${(1000 / ms).toFixed(2)} MB/s)`);
console.log('====================================');
