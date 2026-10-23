/* =============================================================================
 * SM9-10：对标 GM/T 0044（SM9 加密）标准向量 —— 最终版
 *
 * 正式对标点（官方真值来源：guanzhi/GmSSL master tests/sm9test.c 的 hex_de 常量）：
 *   ✔ 标准主密钥 ke → Bob 加密私钥 de_B 四段 128B 逐字节命中官方向量
 *     （覆盖 H1("Bob"‖0x03)、模逆 t2=ke/(H1+ke)、G2 twist 点乘 —— KGC 提取全链路合标）
 *   ✔ 恒等式 e(de_B, C1) == e(P2, Ppub)^r 在标准 ke/r（含前导零小指数）下成立
 *   ✔ 用标准密钥对完成 IBE 加解密自洽往返
 *
 * 密文级(C1/C2/C3 固定 r)对标：公开代码库（GmSSL v2/v3）均无固定 r 的加密示例向量
 * （仅签名有），需 GM/T 0044.5 纸质标准文本 → 挂账 SM9-10 残余，打印我方值供人工核对。
 *
 * 教训重演：脚本初版把 Jacobian 的 Ppub 直接传 point_add/sm9_pairing → 自洽失败；
 * 业务 IBE 层(ppubFromBytes 仿射)无此问题。本版全部先 point_get_affine（SM9-12 同款坑）。
 * ===========================================================================*/
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, 'gmssljs');
const libCode = fs.readFileSync(path.join(dir, 'sm3.js'), 'utf8') + '\n'
              + fs.readFileSync(path.join(dir, 'sm9.js'), 'utf8') + '\n'
              + ';globalThis.__sm9 = { SM9_N, SM9_P2, sm3, point_new, point_mul, point_mul_G, point_add, point_get_affine, twist_point_new, twist_point_mul_G, twist_point_get_affine, fp12_new, fp12_pow, sm9_pairing, fp12_equ };';
eval(libCode);
const G = globalThis.__sm9;
const N = G.SM9_N, HID_ENC = 0x03;

const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
function bigTo32(x) { const o = new Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 255n); x >>= 8n; } return o; }
const xorBytes = (a, b) => a.map((x, i) => x ^ b[i]);
function kdf(Z, kl) { let o = [], ct = 1; while (o.length < kl) { o = o.concat(G.sm3([...Z, ...u32be(ct)])); ct++; } return o.slice(0, kl); }
const mac = (K2, C2) => G.sm3([...C2, ...K2]);
function funcH(prefix, Z, n) {
  const nb = n.toString(2).length, hl = Math.ceil((5 * nb) / 32); let Ha = [], ct = 1;
  while (Ha.length < hl) { Ha = Ha.concat(G.sm3([prefix, ...Z, ...u32be(ct)])); ct++; }
  return (bytesToBig(Ha.slice(0, hl)) % (n - 1n)) + 1n;
}
const H1 = (id, hid) => funcH(0x01, [...id, hid], N);
function modInv(a, n) { let [t, nt, r, nr] = [0n, 1n, n, a % n]; while (nr) { const q = r / nr; [t, nt] = [nt, t - q * nt]; [r, nr] = [nr, r - q * nr]; } return ((t % n) + n) % n; }
const hex32 = (x) => x.toString(16).padStart(64, '0');
const hexArr = (a) => a.map((b) => b.toString(16).padStart(2, '0')).join('');

let pass = 0, fail = 0;
const ok = (n, c, extra = '') => { c ? (pass++, console.log('  ✅', n)) : (fail++, console.log('  ❌', n)); if (extra) console.log(extra); };

// ============ 官方向量（guanzhi/GmSSL tests/sm9test.c）============
const KE = 0x0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22n;
const OFFICIAL_DE = (
  '94736ACD2C8C8796CC4785E938301A139A059D3537B6414140B2D31EECF41683' +   // x1
  '115BAE85F5D8BC6C3DBD9E5342979ACCCF3C2F4F28420B1CB4F8C0B59A19B158' +   // x0
  '7AA5E47570DA7600CD760A0CF7BEAF71C447F3844753FE74FA7BA92CA7D3B55F' +   // y1
  '27538A62E7F7BFB51DCE08704796D94C9D56734F119EA44732B50E31CDEB75C1'     // y0
).toLowerCase();
const ID_BOB = [0x42, 0x6F, 0x62];   // "Bob"
const R = 0x0000AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785Cn;
const M = [...Buffer.from('Chinese IBS standard', 'ascii')];   // 官方明文（20B）

console.log('\n======== SM9-10：GM/T 0044 标准向量对标（最终版）========');

// ---- 1. de_B 提取对标官方向量（核心断言）----
const h1 = H1(ID_BOB, HID_ENC);
const t1 = (h1 + KE) % N;
const t2 = (KE * modInv(t1, N)) % N;
const de = G.twist_point_new(); G.twist_point_mul_G(de, t2);
const da = G.twist_point_new(); G.twist_point_get_affine(da, de);
const myDe = hex32(da.X[1]) + hex32(da.X[0]) + hex32(da.Y[1]) + hex32(da.Y[0]);
ok('标准 ke → de_B 四段 128B 逐字节命中 GmSSL 官方向量（H1/模逆/G2点乘全链路合标）',
  myDe === OFFICIAL_DE, myDe === OFFICIAL_DE ? '' : `      实际=${myDe}\n      官方=${OFFICIAL_DE}`);

// ---- 2. Ppub / C1（供论文核对 0044.5 文本；全程仿射化）----
const PpubJ = G.point_new(); G.point_mul_G(PpubJ, KE);
const Ppub = G.point_new(); G.point_get_affine(Ppub, PpubJ);
console.log('  · Ppub-e = [ke]P1（供对照 0044.5）:');
console.log(`      x=${hex32(Ppub.X)}\n      y=${hex32(Ppub.Y)}`);

const tP = G.point_new(); G.point_mul_G(tP, h1);
const QBj = G.point_new(); G.point_add(QBj, tP, Ppub);          // Ppub 已仿射
const QBa = G.point_new(); G.point_get_affine(QBa, QBj);
const C1j = G.point_new(); G.point_mul(C1j, R, QBa);
const C1a = G.point_new(); G.point_get_affine(C1a, C1j);
console.log('  · C1 = [r]QB（标准 r，供对照 0044.5）:');
console.log(`      x=${hex32(C1a.X)}\n      y=${hex32(C1a.Y)}`);

// ---- 3. 恒等式：e(de,C1) == e(P2,Ppub)^r（标准小指数下）----
const g = G.fp12_new(); G.sm9_pairing(g, G.SM9_P2, Ppub);
const w = G.fp12_new(); G.fp12_pow(w, g, R);
const w2 = G.fp12_new(); G.sm9_pairing(w2, da, C1a);
ok('恒等式 e(de_B, C1) == e(P2, Ppub)^r（标准前导零小指数无边界问题）', G.fp12_equ(w, w2));

// ---- 4. 标准密钥对下的 IBE 加解密自洽往返 ----
const c1Bytes = [...bigTo32(C1a.X), ...bigTo32(C1a.Y)];
function fp12ToBytes(f) { const o = []; for (const fp4 of f) for (const fp2 of fp4) for (const c of fp2) o.push(...bigTo32(c)); return o; }
const Z = [...c1Bytes, ...fp12ToBytes(w), ...ID_BOB];
const K = kdf(Z, M.length + 32), K1 = K.slice(0, M.length), K2 = K.slice(M.length);
const C2 = xorBytes(M, K1), C3 = mac(K2, C2);
console.log(`  · 我方密文（标准 r，供对照 0044.5）: C2=${hexArr(C2)}\n      C3=${hexArr(C3)}`);

const Z2 = [...c1Bytes, ...fp12ToBytes(w2), ...ID_BOB];
const Kp = kdf(Z2, C2.length + 32), K1p = Kp.slice(0, C2.length), K2p = Kp.slice(C2.length);
const Mp = xorBytes(C2, K1p);
ok('标准密钥对 IBE 自洽往返（解密 == "Chinese IBS standard" 且 MAC 通过）',
  Buffer.from(Mp).toString('ascii') === 'Chinese IBS standard'
  && mac(K2p, C2).join(',') === C3.join(','));

console.log(`\n======== 结果：${pass} 通过 / ${fail} 失败 ========`);
process.exit(fail === 0 ? 0 : 1);
