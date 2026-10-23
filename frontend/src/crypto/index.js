// 浏览器加密门面：加载 vendored gmssl → 组装高层套件。页面只 import 此处。
import G from './gmssl.js';
import { createSecureDoc } from './secure-doc.js';
import { b64ToBytes, bytesToB64, utf8ToBytes, bytesToUtf8 } from './b64.js';

export const secureDoc = createSecureDoc(G);
export { b64ToBytes, bytesToB64, utf8ToBytes, bytesToUtf8 };
