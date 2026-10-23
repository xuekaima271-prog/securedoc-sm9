// 纯 JS Base64（标准字母表，含填充）。环境无关：浏览器与 Node 都可用，避免 btoa/Buffer 分叉。
const TBL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const REV = (() => { const r = new Int16Array(128).fill(-1); for (let i = 0; i < TBL.length; i++) r[TBL.charCodeAt(i)] = i; return r; })();

/** byte[]（0..255 的数字数组或 Uint8Array）→ base64 字符串 */
export function bytesToB64(bytes) {
  let out = '';
  const n = bytes.length;
  for (let i = 0; i < n; i += 3) {
    const b0 = bytes[i] & 0xff;
    const b1 = i + 1 < n ? bytes[i + 1] & 0xff : 0;
    const b2 = i + 2 < n ? bytes[i + 2] & 0xff : 0;
    out += TBL[b0 >> 2];
    out += TBL[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < n ? TBL[((b1 & 15) << 2) | (b2 >> 6)] : '=';
    out += i + 2 < n ? TBL[b2 & 63] : '=';
  }
  return out;
}

/** base64 字符串 → number[]（0..255） */
export function b64ToBytes(s) {
  const clean = s.replace(/[^A-Za-z0-9+/]/g, '');
  const out = [];
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = REV[clean.charCodeAt(i)];
    const c1 = REV[clean.charCodeAt(i + 1)];
    const c2 = i + 2 < clean.length ? REV[clean.charCodeAt(i + 2)] : -1;
    const c3 = i + 3 < clean.length ? REV[clean.charCodeAt(i + 3)] : -1;
    out.push((c0 << 2) | (c1 >> 4));
    if (c2 >= 0) out.push(((c1 & 15) << 4) | (c2 >> 2));
    if (c3 >= 0) out.push(((c2 & 3) << 6) | c3);
  }
  return out;
}

/** UTF-8 字符串 → byte[] */
export function utf8ToBytes(s) {
  return [...new TextEncoder().encode(s)];
}

/** byte[] → UTF-8 字符串 */
export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(new Uint8Array(bytes));
}
