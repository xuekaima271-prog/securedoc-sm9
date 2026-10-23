// =============================================================================
// 国密能力 PoC —— 文档 §18.11「第一步：国密能力 PoC」交付物
// 目标：在写任何业务代码前，用真实代码证明本系统的密码主线可落地：
//   1) SM3 摘要正确（已知向量校验）
//   2) SM4 文件内容加解密往返一致（文件密文层）
//   3) SM9 KGC 主密钥 + 按身份签发私钥 + 封装/解封 SM4 文件密钥(DEK)
//   4) 非接收人(错误身份/私钥)无法解封 —— 证明身份绑定的访问控制
//   5) SM9 签名验签 + 篡改检测 —— 防抵赖/防信封替换
//   6) 端到端串联：封装DEK -> SM4加密文件 -> 解封DEK -> SM4解密 -> 还原
// 库：@lryncloud/crypto（纯 JS，可进浏览器）
// =============================================================================
import { randomBytes } from 'node:crypto';
import {
  sm3Hex,
  sm4EncryptCbc, sm4DecryptCbc,
  sm9CreateMasterKeyPair,
  sm9DeriveEncryptPrivateKey,
  sm9DeriveSignPrivateKey,
  sm9Encrypt, sm9Decrypt,
  sm9Sign, sm9Verify,
} from '@lryncloud/crypto';

let pass = 0, fail = 0;
const ok  = (name, cond, extra = '') => { (cond ? (pass++, console.log(`  ✅ PASS  ${name}`)) : (fail++, console.log(`  ❌ FAIL  ${name}`))); if (extra) console.log(`         ${extra}`); };
const ms  = (t0) => `${(Number(process.hrtime.bigint() - t0) / 1e6).toFixed(1)} ms`;
const sect = (s) => console.log(`\n=== ${s} ===`);

// 演示身份（取自设计文档 §2.2.4 身份标识格式 user:{tenant}:{userId}:{email}）
const ID_BOB   = 'user:corp001:10002:bob@example.com';
const ID_CAROL = 'user:corp001:10003:carol@example.com';
const ID_ALICE = 'user:corp001:10001:alice@example.com';

console.log('############ 国密能力 PoC 开始 ############');

// -----------------------------------------------------------------------------
sect('1. SM3 摘要（已知向量校验）');
// GB/T 32905-2016 标准向量: SM3("abc")
const SM3_ABC = '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0';
const d = sm3Hex('abc');
ok('SM3("abc") 命中国标向量', d === SM3_ABC, `got=${d}`);

// -----------------------------------------------------------------------------
sect('2. SM4 文件内容加解密往返（文件密文层）');
const sm4Key = randomBytes(16).toString('hex');      // 一次性 SM4 文件密钥 DEK
const sm4Iv  = randomBytes(16).toString('hex');
const plain  = '这是一份机密合同的正文内容：甲方……乙方……金额￥1,234,567.89。';
const ct  = sm4EncryptCbc(plain, sm4Key, { iv: sm4Iv, padding: true, output: 'base64' });
const rt  = sm4DecryptCbc(ct, sm4Key, { iv: sm4Iv, input: 'base64', output: 'utf8', padding: true });
ok('SM4-CBC 加密后解密还原一致', rt === plain, `cipher(base64, 前32)=${ct.slice(0,32)}...`);

// -----------------------------------------------------------------------------
sect('3. SM9：KGC 主密钥 + 按身份签发私钥 + 封装/解封 DEK');
let t0 = process.hrtime.bigint();
const master = sm9CreateMasterKeyPair('0130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f401');
console.log(`  · KGC 主密钥生成: ${ms(t0)}  （含 masterPublic[签名] / masterEncryptPublic[加密]）`);

t0 = process.hrtime.bigint();
const bobEncPriv = sm9DeriveEncryptPrivateKey(ID_BOB, master.masterSecret);   // KGC 按 Bob 身份签发加密私钥
console.log(`  · KGC 为 Bob 签发 SM9 加密私钥: ${ms(t0)}`);

// 发送方 Alice 浏览器：用 Bob 的【身份】封装一次性 DEK（无需 Bob 公钥/证书）
const dek    = randomBytes(16);                       // 待封装的 SM4 文件密钥
const dekHex = dek.toString('hex');
t0 = process.hrtime.bigint();
const envelopeForBob = sm9Encrypt(dek, { userId: ID_BOB, masterEncryptPublicHex: master.masterEncryptPublic, output: 'base64' });
console.log(`  · Alice 用 Bob 身份封装 DEK(sm9Encrypt): ${ms(t0)}`);

// 接收方 Bob 浏览器：用自己的 SM9 私钥解封 DEK
t0 = process.hrtime.bigint();
const dekBack = sm9Decrypt(envelopeForBob, { userId: ID_BOB, encryptPrivateKeyHex: bobEncPriv, input: 'base64', output: 'hex' });
console.log(`  · Bob 用自己私钥解封 DEK(sm9Decrypt): ${ms(t0)}`);
ok('SM9 封装→解封 还原出同一个 DEK', dekBack === dekHex, `DEK=${dekHex}`);

// -----------------------------------------------------------------------------
sect('4. 访问控制：非接收人无法解封（身份绑定）');
const carolEncPriv = sm9DeriveEncryptPrivateKey(ID_CAROL, master.masterSecret);
let carolFailed = false, carolOut = null;
try {
  // Carol 拿自己的身份 + 自己的私钥，去解 发给 Bob 的信封
  carolOut = sm9Decrypt(envelopeForBob, { userId: ID_CAROL, encryptPrivateKeyHex: carolEncPriv, input: 'base64', output: 'hex' });
  carolFailed = (carolOut !== dekHex);           // 没抛错也必须解不出正确 DEK
} catch (e) {
  carolFailed = true; carolOut = `抛出异常: ${e.message}`;
}
ok('非接收人 Carol 无法解出 DEK', carolFailed, `carol结果=${carolOut}`);

// -----------------------------------------------------------------------------
sect('5. SM9 签名/验签 + 篡改检测（防抵赖 / 防信封替换）');
const aliceSignPriv = sm9DeriveSignPrivateKey(ID_ALICE, master.masterSecret);
// 对“投递清单摘要”签名：文件ID + 接收人 + 信封摘要 + 元数据摘要
const manifest = sm3Hex(`fileId=uuid-001|to=${ID_BOB}|env=${sm3Hex(envelopeForBob)}|meta=${sm3Hex(plain)}`);
t0 = process.hrtime.bigint();
const sig = sm9Sign(manifest, ID_ALICE, aliceSignPriv);
const signMs = ms(t0);
t0 = process.hrtime.bigint();
const verifyGood = sm9Verify(manifest, ID_ALICE, sig, master.masterPublic);
console.log(`  · 签名: ${signMs}，验签: ${ms(t0)}`);
ok('Alice 签名可被验证通过', verifyGood === true);
const verifyTampered = sm9Verify(sm3Hex('被篡改的清单'), ID_ALICE, sig, master.masterPublic);
ok('清单被篡改后验签失败', verifyTampered === false);

// -----------------------------------------------------------------------------
sect('6. 端到端串联：封装DEK → SM4加密文件 → 解封DEK → SM4解密 → 还原');
const fileText = 'E2E 验证：文件明文只应出现在发送/接收浏览器，服务器只见密文。'.repeat(20);
const fileIv   = randomBytes(16).toString('hex');
// 发送端：DEK 已被 SM9 封装进 envelopeForBob；用 DEK 加密文件
const fileCt   = sm4EncryptCbc(fileText, dekHex, { iv: fileIv, padding: true, output: 'base64' });
// —— 此处 fileCt + envelopeForBob 即“上传到服务器的内容”，服务器无法解 ——
// 接收端：先解封 DEK，再解文件
const dekAtBob   = sm9Decrypt(envelopeForBob, { userId: ID_BOB, encryptPrivateKeyHex: bobEncPriv, input: 'base64', output: 'hex' });
const filePlain  = sm4DecryptCbc(fileCt, dekAtBob, { iv: fileIv, input: 'base64', output: 'utf8', padding: true });
ok('端到端：接收端完整还原文件明文', filePlain === fileText, `原文长度=${fileText.length}, 还原长度=${filePlain.length}`);

// -----------------------------------------------------------------------------
console.log(`\n############ 结果：${pass} 通过 / ${fail} 失败 ############`);
process.exit(fail === 0 ? 0 : 1);
