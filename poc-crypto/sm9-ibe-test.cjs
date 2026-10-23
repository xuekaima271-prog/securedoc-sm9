/* =============================================================================
 * SM9 IBE 加解密层 —— 基于 guanzhi/GmSSL-JS 的真实配对/曲线实现（GM/T 0044）
 * 目标：证明真 SM9 能在 JS(浏览器可移植) 完成"按身份封装 DEK / 用私钥解封"，
 *      并验证 配对命中国标向量 + 往返成功 + 非接收人解封失败。
 * 说明：该库只到配对，无 IBE 层；本文件按 GM/T 0044.3 补 keygen/extract/encrypt/decrypt。
 *      KDF 自实现（库内 sm3_kdf 有 bug）。MAC 用 SM3(C2||K2)。
 * ===========================================================================*/
// 注意：不能 'use strict'，guanzhi 库用了 delete ctx（严格模式禁止）；
// 且 sloppy 模式下 eval 的函数声明会泄漏到本作用域，正好供下方调用。
const fs = require('fs');
const path = require('path');
const { randomBytes } = require('crypto');

// ---- 加载 guanzhi 库（函数 sloppy-eval 泄漏；const 常量不泄漏，故在 eval 内挂到 globalThis 再解构）----
const dir = path.join(__dirname, 'gmssljs');
// 仅常量（const，不泄漏）需经 globalThis 导出；函数（function）sloppy-eval 已泄漏到本作用域，直接裸用
const libCode = fs.readFileSync(path.join(dir, 'sm3.js'), 'utf8') + '\n'
              + fs.readFileSync(path.join(dir, 'sm9.js'), 'utf8') + '\n'   // 末尾自动 pairing_test() 打印 true
              + ';globalThis.__sm9 = { SM9_N, SM9_P2 };';
eval(libCode); // eslint-disable-line no-eval
const { SM9_N, SM9_P2 } = globalThis.__sm9;

const N = SM9_N;            // 群阶
const HID_ENC = 0x03;      // 加密用 hid（GM/T 0044）

// ---------- 字节/大数工具 ----------
const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
function bigTo32(x) { const o = new Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 255n); x >>= 8n; } return o; }
function xorBytes(a, b) { const o = new Array(a.length); for (let i = 0; i < a.length; i++) o[i] = a[i] ^ b[i]; return o; }
function randScalar() { let k; do { k = bytesToBig([...randomBytes(40)]) % N; } while (k === 0n); return k; }
function modInv(a, m) { let [old_r, r] = [((a % m) + m) % m, m], [old_s, s] = [1n, 0n];
  while (r !== 0n) { const q = old_r / r; [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; }
  return ((old_s % m) + m) % m; }

// ---------- 自实现 KDF / MAC / H1 ----------
function kdf(Z, klenBytes) { let out = []; let ct = 1; while (out.length < klenBytes) { out = out.concat(sm3([...Z, ...u32be(ct)])); ct++; } return out.slice(0, klenBytes); }
function mac(K2, C2) { return sm3([...C2, ...K2]); }                // GM/T 0044: MAC(K,Z)=Hash(Z||K)
function funcH(prefix, Z, n) {
  const nbits = n.toString(2).length;
  const hlenBytes = Math.ceil((5 * nbits) / 32);                    // SM9: 40 字节
  let Ha = []; let ct = 1;
  while (Ha.length < hlenBytes) { Ha = Ha.concat(sm3([prefix, ...Z, ...u32be(ct)])); ct++; }
  Ha = Ha.slice(0, hlenBytes);
  return (bytesToBig(Ha) % (n - 1n)) + 1n;
}
const H1 = (idBytes, hid) => funcH(0x01, [...idBytes, hid], N);

// ---------- 点序列化（仿射，G1: x||y 64字节）----------
function g1Affine(P) { const a = point_new(); point_get_affine(a, P); return a; }
function g1ToBytes(P) { const a = g1Affine(P); return [...bigTo32(a.X), ...bigTo32(a.Y)]; }
function g1FromBytes(b) { return { X: bytesToBig(b.slice(0, 32)), Y: bytesToBig(b.slice(32, 64)), Z: 1n }; }
function g2Affine(P) { const a = twist_point_new(); twist_point_get_affine(a, P); return a; }
function fp12ToBytes(f) { const o = []; for (const fp4 of f) for (const fp2 of fp4) for (const c of fp2) o.push(...bigTo32(c)); return o; } // 12*32=384

const idToBytes = (s) => [...Buffer.from(s, 'utf8')];

// ---------- KGC：加密主密钥 + 按身份提取私钥（无配对，仅点乘）----------
function encMasterKeyGen() {
  const ke = randScalar();
  const Ppub = point_new(); point_mul_G(Ppub, ke);                 // Ppub-e=[ke]P1 (G1)
  return { ke, Ppub: g1Affine(Ppub) };
}
function encExtractKey(idBytes, ke) {
  const t1 = (H1(idBytes, HID_ENC) + ke) % N;
  if (t1 === 0n) throw new Error('extract: t1=0');
  const t2 = (ke * modInv(t1, N)) % N;
  const de = twist_point_new(); twist_point_mul_G(de, t2);         // de=[t2]P2 (G2)
  return g2Affine(de);
}

// ---------- IBE 加密 / 解密（GM/T 0044.3，KDF+MAC 模式）----------
function ibeEncrypt(M, idBytes, Ppub) {
  const h1 = H1(idBytes, HID_ENC);
  const t = point_new(); point_mul_G(t, h1);                       // [h1]P1
  const QB = point_new(); point_add(QB, t, Ppub);                  // QB=[h1]P1+Ppub-e (G1)
  const QBa = g1Affine(QB);                                        // 关键修复：point_mul 要求仿射基点
  const g = fp12_new(); sm9_pairing(g, SM9_P2, Ppub);             // g=e(Ppub-e,P2)
  for (;;) {
    const r = randScalar();
    const C1 = point_new(); point_mul(C1, r, QBa);                 // C1=[r]QB
    const C1aff = g1Affine(C1);
    const w = fp12_new(); fp12_pow(w, g, r);                       // w=g^r
    const Z = [...g1ToBytes(C1aff), ...fp12ToBytes(w), ...idBytes];
    const K = kdf(Z, M.length + 32);
    const K1 = K.slice(0, M.length), K2 = K.slice(M.length);
    if (K1.every((x) => x === 0)) continue;                        // K1 全零重来
    const C2 = xorBytes(M, K1);
    const C3 = mac(K2, C2);
    return [...g1ToBytes(C1aff), ...C3, ...C2];                    // C1(64)||C3(32)||C2
  }
}
function ibeDecrypt(ct, idBytes, de) {
  const C1 = g1FromBytes(ct.slice(0, 64));
  const C3 = ct.slice(64, 96);
  const C2 = ct.slice(96);
  const w = fp12_new(); sm9_pairing(w, de, C1);                   // w'=e(C1,de)
  const Z = [...ct.slice(0, 64), ...fp12ToBytes(w), ...idBytes];
  const K = kdf(Z, C2.length + 32);
  const K1 = K.slice(0, C2.length), K2 = K.slice(C2.length);
  const M = xorBytes(C2, K1);
  const u = mac(K2, C2);
  if (u.join(',') !== C3.join(',')) throw new Error('SM9 decrypt: MAC 校验失败（非接收人或密文被篡改）');
  return M;
}

// =============================== 测试 ===============================
const hex = (a) => a.map((b) => b.toString(16).padStart(2, '0')).join('');
let pass = 0, fail = 0;
const ok = (n, c, e = '') => { c ? (pass++, console.log('  ✅', n)) : (fail++, console.log('  ❌', n)); if (e) console.log('     ', e); };
const ms = (t0) => `${(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(1)}ms`;

console.log('\n======== SM9 真实现 IBE 测试（基于 guanzhi/GmSSL-JS 真配对）========');

const ID_BOB = idToBytes('user:corp001:10002:bob@example.com');
const ID_CAROL = idToBytes('user:corp001:10003:carol@example.com');

let t0 = process.hrtime.bigint();
const master = encMasterKeyGen();
console.log('  · KGC 生成加密主密钥:', ms(t0));
t0 = process.hrtime.bigint();
const bobKey = encExtractKey(ID_BOB, master.ke);
console.log('  · KGC 为 Bob 提取私钥(无配对):', ms(t0));

// 封装一个 16 字节 SM4 文件密钥 DEK
const DEK = [...randomBytes(16)];
t0 = process.hrtime.bigint();
const envelope = ibeEncrypt(DEK, ID_BOB, master.Ppub);
console.log('  · Alice 用 Bob 身份封装 DEK(含配对):', ms(t0), ' 信封字节:', envelope.length);
t0 = process.hrtime.bigint();
const dekBack = ibeDecrypt(envelope, ID_BOB, bobKey);
console.log('  · Bob 用私钥解封 DEK(含配对):', ms(t0));
ok('SM9 封装→解封 还原同一 DEK', hex(dekBack) === hex(DEK), 'DEK=' + hex(DEK));

// 非接收人：Carol 用自己私钥解 Bob 的信封 → 必须失败。
// 关键：用 Bob 的身份串(ID_BOB) + Carol 的私钥，专门验证「私钥本身参与解密绑定」，
// 而非仅靠 KDF 里的身份串区分（后者会掩盖 sm3 多分块/配对类 bug）。
const carolKey = encExtractKey(ID_CAROL, master.ke);
let carolFailed = false, info = '';
try { const r = ibeDecrypt(envelope, ID_BOB, carolKey); carolFailed = hex(r) !== hex(DEK); info = '解出但不等(危险!)'; }
catch (e) { carolFailed = true; info = e.message; }
ok('非接收人 Carol 私钥(对身份串)无法解封', carolFailed, info);

// 篡改密文 → 必须失败
const tampered = envelope.slice(); tampered[96] ^= 0x01;
let tamperFailed = false;
try { ibeDecrypt(tampered, ID_BOB, bobKey); } catch (e) { tamperFailed = true; }
ok('密文被篡改后解封失败', tamperFailed);

console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
process.exit(fail === 0 ? 0 : 1);
