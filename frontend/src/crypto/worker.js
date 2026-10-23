/* =============================================================================
 * 加密 Web Worker（FE-1）：把 SM4/SM3/SM9 重计算移出主线程，页面不再卡顿，
 * 且加密阶段可逐块上报进度。与主线程共用同一 crypto/ 模块（演示路径==被测路径）。
 *
 * 协议：postMessage({ id, cmd, p })
 *   cmd=seal        p={fileBuffer(转移), metadata, recipients, masterPublicKeyBytes, chunkSize}
 *   cmd=unwrapDek   p={keyEnvelope, identity, privateKeyBytes}
 *   cmd=openChunk   p={dek, ivB64, ciphertext, expectDigestB64}
 *   cmd=openMetadata p={dek, encryptedMetadata}
 * 回复：{id, type:'progress', done, total} | {id, type:'done', result} | {id, type:'error', message}
 * ===========================================================================*/
import G from './gmssl.js';
import { createSecureDoc } from './secure-doc.js';

const sdoc = createSecureDoc(G);

self.onmessage = (e) => {
  const { id, cmd, p } = e.data;
  const post = (m, transfer) => self.postMessage({ id, ...m }, transfer || []);
  try {
    if (cmd === 'seal') {
      const fileBytes = Array.from(new Uint8Array(p.fileBuffer));
      const sealed = sdoc.sealFile({
        fileBytes, metadata: p.metadata, recipients: p.recipients,
        masterPublicKeyBytes: p.masterPublicKeyBytes, chunkSize: p.chunkSize,
        onProgress: (done, total) => post({ type: 'progress', done, total }),
      });
      // 密文转 Uint8Array 以零拷贝转移回主线程（50MB 级别避免结构化克隆开销）
      const buffers = [];
      sealed.chunks = sealed.chunks.map((c) => {
        const u = Uint8Array.from(c.ciphertext);
        buffers.push(u.buffer);
        return { ...c, ciphertext: u };
      });
      post({ type: 'done', result: sealed }, buffers);
    } else if (cmd === 'unwrapDek') {
      post({ type: 'done', result: sdoc.unwrapDek(p) });
    } else if (cmd === 'openChunk') {
      const plain = Uint8Array.from(sdoc.openChunk(p));
      post({ type: 'done', result: plain }, [plain.buffer]);
    } else if (cmd === 'openMetadata') {
      post({ type: 'done', result: sdoc.openMetadata(p) });
    } else {
      throw new Error(`未知命令: ${cmd}`);
    }
  } catch (err) {
    post({ type: 'error', message: err?.message || String(err) });
  } finally {
    p?.privateKeyBytes?.fill(0);
    p?.dek?.fill(0);
  }
};
