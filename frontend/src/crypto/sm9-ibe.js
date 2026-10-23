// SM9 IBE 加解密层（封装/解封 DEK）。逐字移植自 poc-crypto/kgc-service-interop.cjs（7/7 闸门参考实现）。
// 传入 gmssl 命名空间 G，使浏览器与 Node E2E 闸门共用同一逻辑。
import { utf8ToBytes } from './b64.js';

function defaultRandomBytes(n) {
  const a = new Uint8Array(n);
  globalThis.crypto.getRandomValues(a);
  return [...a];
}

export function createIbe(G, randomBytes = defaultRandomBytes) {
  const {
    sm3, point_new, point_mul, point_mul_G, point_add, point_get_affine,
    fp12_new, fp12_pow, sm9_pairing, SM9_N, SM9_P2,
  } = G;
  const N = SM9_N, HID_ENC = 0x03;

  const u32be = (x) => [(x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
  const bytesToBig = (a) => a.reduce((acc, b) => (acc << 8n) + BigInt(b), 0n);
  function bigTo32(x) { const o = new Array(32); for (let i = 31; i >= 0; i--) { o[i] = Number(x & 255n); x >>= 8n; } return o; }
  const xorBytes = (a, b) => a.map((x, i) => x ^ b[i]);
  function kdf(Z, kl) { let o = [], ct = 1; while (o.length < kl) { o = o.concat(sm3([...Z, ...u32be(ct)])); ct++; } return o.slice(0, kl); }
  const mac = (K2, C2) => sm3([...C2, ...K2]);
  function funcH(prefix, Z, n) {
    const nb = n.toString(2).length, hl = Math.ceil((5 * nb) / 32); let Ha = [], ct = 1;
    while (Ha.length < hl) { Ha = Ha.concat(sm3([prefix, ...Z, ...u32be(ct)])); ct++; }
    return (bytesToBig(Ha.slice(0, hl)) % (n - 1n)) + 1n;
  }
  const H1 = (id, hid) => funcH(0x01, [...id, hid], N);
  function g1Affine(P) { const a = point_new(); point_get_affine(a, P); return a; }
  function g1ToBytes(P) { const a = g1Affine(P); return [...bigTo32(a.X), ...bigTo32(a.Y)]; }
  function fp12ToBytes(f) { const o = []; for (const fp4 of f) for (const fp2 of fp4) for (const c of fp2) o.push(...bigTo32(c)); return o; }

  /** 身份串 → 字节 */
  const idToBytes = (s) => utf8ToBytes(s);
  /** 主公钥字节(64B: x||y) → G1 点 */
  const ppubFromBytes = (b) => ({ X: bytesToBig(b.slice(0, 32)), Y: bytesToBig(b.slice(32, 64)), Z: 1n });
  /** 用户私钥字节(128B: x0||x1||y0||y1) → G2 点 */
  const deFromBytes = (b) => ({
    X: [bytesToBig(b.slice(0, 32)), bytesToBig(b.slice(32, 64))],
    Y: [bytesToBig(b.slice(64, 96)), bytesToBig(b.slice(96, 128))], Z: [1n, 0n],
  });

  /** IBE 封装：用接收人身份 + 主公钥 把消息 M(byte[]) 封成密文 byte[]（C1||C3(mac)||C2） */
  function ibeEncrypt(M, idBytes, Ppub) {
    const h1 = H1(idBytes, HID_ENC);
    const t = point_new(); point_mul_G(t, h1);
    const QB = point_new(); point_add(QB, t, Ppub);
    const QBa = g1Affine(QB);   // 关键修复：point_mul 需仿射基点
    const g = fp12_new(); sm9_pairing(g, SM9_P2, Ppub);
    for (;;) {
      const r = (bytesToBig(randomBytes(40)) % N) || 1n;
      const C1 = point_new(); point_mul(C1, r, QBa); const C1a = g1Affine(C1);
      const w = fp12_new(); fp12_pow(w, g, r);
      const Z = [...g1ToBytes(C1a), ...fp12ToBytes(w), ...idBytes];
      const K = kdf(Z, M.length + 32), K1 = K.slice(0, M.length), K2 = K.slice(M.length);
      if (K1.every((x) => x === 0)) continue;
      return [...g1ToBytes(C1a), ...mac(K2, xorBytes(M, K1)), ...xorBytes(M, K1)];
    }
  }

  /** IBE 解封：用身份 + 私钥 de 还原 M；MAC 不符抛错（防篡改/非接收人） */
  function ibeDecrypt(ct, idBytes, de) {
    const C1 = { X: bytesToBig(ct.slice(0, 32)), Y: bytesToBig(ct.slice(32, 64)), Z: 1n };
    const C3 = ct.slice(64, 96), C2 = ct.slice(96);
    const w = fp12_new(); sm9_pairing(w, de, C1);
    const Z = [...ct.slice(0, 64), ...fp12ToBytes(w), ...idBytes];
    const K = kdf(Z, C2.length + 32), K1 = K.slice(0, C2.length), K2 = K.slice(C2.length);
    const M = xorBytes(C2, K1);
    if (mac(K2, C2).join(',') !== C3.join(',')) throw new Error('SM9 解封 MAC 校验失败（非接收人或密文被篡改）');
    return M;
  }

  return { ibeEncrypt, ibeDecrypt, idToBytes, ppubFromBytes, deFromBytes };
}
