// 高层端到端文档加密套件：发送(sealFile) / 接收(unwrapDek+openChunk+openMetadata)。
// 浏览器页面与 Node E2E 闸门共用此模块，确保「演示路径 == 被测路径」。
import { createIbe } from './sm9-ibe.js';
import { createFileCrypto } from './file-crypto.js';
import { bytesToB64, b64ToBytes } from './b64.js';

export function createSecureDoc(G, randomBytes) {
  const ibe = createIbe(G, randomBytes);
  const fc = createFileCrypto(G, randomBytes);

  /**
   * 发送侧：生成随机 DEK → SM4 分块加密文件 → SM4 加密元数据 → 为每个接收人用 SM9 封装 DEK。
   * @returns {{encryptedMetadata, recipients, chunks, chunkSize, chunkCount, totalSize}}
   *   chunks: [{index, ivB64, digestB64, ciphertext(byte[])}]
   */
  function sealFile({ fileBytes, metadata, recipients, masterPublicKeyBytes, chunkSize = 1 << 20, onProgress }) {
    const dek = fc.genDek();
    const Ppub = ibe.ppubFromBytes(masterPublicKeyBytes);

    const chunkCount = Math.max(1, Math.ceil(fileBytes.length / chunkSize));
    const chunks = [];
    let totalSize = 0;
    for (let i = 0; i < chunkCount; i++) {
      const slice = [...fileBytes.slice(i * chunkSize, (i + 1) * chunkSize)];
      const c = fc.encryptChunk(dek, slice);
      chunks.push({ index: i, ivB64: c.ivB64, digestB64: c.digestB64, ciphertext: c.ciphertext });
      totalSize += c.ciphertext.length;
      onProgress?.(i + 1, chunkCount);   // Worker 里转发为进度消息；同步调用方可忽略
    }

    const encryptedMetadata = fc.encryptMetadata(dek, metadata);
    const dekDigestB64 = bytesToB64(fc.sm3Digest(dek));

    const recs = recipients.map((r) => {
      const wrapped = ibe.ibeEncrypt(dek, ibe.idToBytes(r.identity), Ppub);
      return {
        recipientId: r.userId,
        recipientIdentity: r.identity,
        keyEnvelope: {
          algorithm: 'SM9',
          recipientIdentity: r.identity,
          wrappedKey: bytesToB64(wrapped),
          keyDigest: dekDigestB64,
        },
      };
    });

    return { encryptedMetadata, recipients: recs, chunks, chunkSize, chunkCount, totalSize };
  }

  /** 接收侧：用本地 SM9 私钥解封信封得到 DEK（含 DEK 摘要校验）。 */
  function unwrapDek({ keyEnvelope, identity, privateKeyBytes }) {
    const de = ibe.deFromBytes(privateKeyBytes);
    const dek = ibe.ibeDecrypt(b64ToBytes(keyEnvelope.wrappedKey), ibe.idToBytes(identity), de);
    if (keyEnvelope.keyDigest && bytesToB64(fc.sm3Digest(dek)) !== keyEnvelope.keyDigest) {
      throw new Error('解封得到的 DEK 摘要不符');
    }
    return dek;
  }

  /** 接收侧：校验密文分块 SM3（防篡改）后用 DEK 解密为明文分块。 */
  function openChunk({ dek, ivB64, ciphertext, expectDigestB64 }) {
    if (expectDigestB64 && fc.sm3DigestB64(ciphertext) !== expectDigestB64) {
      throw new Error('密文分块 SM3 校验失败（疑似被篡改）');
    }
    return fc.decryptChunk(dek, b64ToBytes(ivB64), ciphertext);
  }

  /** 接收侧：解密元数据（文件名/MIME/备注）。 */
  function openMetadata({ dek, encryptedMetadata }) {
    return fc.decryptMetadata(dek, encryptedMetadata);
  }

  return { sealFile, unwrapDek, openChunk, openMetadata, ibe, fc };
}
