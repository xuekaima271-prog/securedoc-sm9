// SM4-CBC（PKCS#7）+ SM3 摘要 + DEK/IV 生成 + 元数据封装。基于 vendored guanzhi 的 SM4 单块原语。
import { bytesToB64, b64ToBytes, utf8ToBytes, bytesToUtf8 } from './b64.js';

function defaultRandomBytes(n) {
  const a = new Uint8Array(n);
  globalThis.crypto.getRandomValues(a);
  return [...a];
}

export function createFileCrypto(G, randomBytes = defaultRandomBytes) {
  const { sm3, sm4_key_new, sm4_set_encrypt_key, sm4_set_decrypt_key, sm4_encrypt } = G;
  const BLOCK = 16;

  function pkcs7Pad(data) {
    const pad = BLOCK - (data.length % BLOCK) || BLOCK; // 整除时也补满一块
    const out = data.slice();
    for (let i = 0; i < pad; i++) out.push(pad);
    return out;
  }
  function pkcs7Unpad(data) {
    if (data.length === 0 || data.length % BLOCK !== 0) throw new Error('SM4 密文长度非法');
    const pad = data[data.length - 1];
    if (pad < 1 || pad > BLOCK) throw new Error('PKCS7 填充非法');
    for (let i = data.length - pad; i < data.length; i++) {
      if (data[i] !== pad) throw new Error('PKCS7 填充校验失败');
    }
    return data.slice(0, data.length - pad);
  }

  function sm4CbcEncrypt(keyBytes, ivBytes, plain) {
    const key = sm4_key_new(); sm4_set_encrypt_key(key, keyBytes);
    const padded = pkcs7Pad([...plain]);
    const out = new Array(padded.length);
    let prev = [...ivBytes];
    for (let off = 0; off < padded.length; off += BLOCK) {
      const x = new Array(BLOCK);
      for (let i = 0; i < BLOCK; i++) x[i] = padded[off + i] ^ prev[i];
      const ob = new Array(BLOCK);
      sm4_encrypt(x, 0, ob, 0, key);
      for (let i = 0; i < BLOCK; i++) out[off + i] = ob[i];
      prev = ob;
    }
    return out;
  }
  function sm4CbcDecrypt(keyBytes, ivBytes, cipher) {
    const key = sm4_key_new(); sm4_set_decrypt_key(key, keyBytes);
    if (cipher.length % BLOCK !== 0) throw new Error('SM4 密文长度非法');
    const out = new Array(cipher.length);
    let prev = [...ivBytes];
    for (let off = 0; off < cipher.length; off += BLOCK) {
      const block = cipher.slice(off, off + BLOCK);
      const db = new Array(BLOCK);
      sm4_encrypt(block, 0, db, 0, key);   // 解密 = 用解密轮密钥跑同一轮函数
      for (let i = 0; i < BLOCK; i++) out[off + i] = db[i] ^ prev[i];
      prev = block;
    }
    return pkcs7Unpad(out);
  }

  const sm3Digest = (bytes) => sm3([...bytes]);
  const sm3DigestB64 = (bytes) => bytesToB64(sm3([...bytes]));
  const genDek = () => randomBytes(16);
  const genIv = () => randomBytes(16);

  /** 加密一个明文分块 → {ivB64, digestB64(密文SM3), ciphertext(byte[])} */
  function encryptChunk(dek, plainChunk) {
    const iv = genIv();
    const ciphertext = sm4CbcEncrypt(dek, iv, plainChunk);
    return { ivB64: bytesToB64(iv), digestB64: sm3DigestB64(ciphertext), ciphertext };
  }
  function decryptChunk(dek, ivBytes, cipher) {
    return sm4CbcDecrypt(dek, ivBytes, cipher);
  }

  /** 加密元数据对象 → {algorithm,mode,iv,ciphertext,digest}（§18.6.1/§18.9.3） */
  function encryptMetadata(dek, metaObj) {
    const iv = genIv();
    const plain = utf8ToBytes(JSON.stringify(metaObj));
    const ct = sm4CbcEncrypt(dek, iv, plain);
    return { algorithm: 'SM4', mode: 'CBC', iv: bytesToB64(iv), ciphertext: bytesToB64(ct), digest: sm3DigestB64(plain) };
  }
  function decryptMetadata(dek, encMeta) {
    const iv = b64ToBytes(encMeta.iv);
    const ct = b64ToBytes(encMeta.ciphertext);
    const plain = sm4CbcDecrypt(dek, iv, ct);
    if (encMeta.digest && bytesToB64(sm3(plain)) !== encMeta.digest) {
      throw new Error('元数据完整性校验失败');
    }
    return JSON.parse(bytesToUtf8(plain));
  }

  return {
    sm4CbcEncrypt, sm4CbcDecrypt, sm3Digest, sm3DigestB64,
    genDek, genIv, encryptChunk, decryptChunk, encryptMetadata, decryptMetadata,
  };
}
