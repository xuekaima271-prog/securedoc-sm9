# Step 1 国密能力 PoC —— 结论

对应设计文档《项目目录与落地路线图》§18.11「第一步：国密能力 PoC」。

## 结论：国密混合加密主线可落地 ✅

用真实代码（`poc.mjs`，可 `node poc.mjs` 复现）验证了系统密码主线，7/7 全部通过。

| # | 验证项 | 结果 |
|---|---|---|
| 1 | SM3("abc") 命中 GB/T 32905-2016 国标向量 | ✅ |
| 2 | SM4-CBC 文件加解密往返一致（文件密文层） | ✅ |
| 3 | SM9：KGC 主密钥 → 按身份签发私钥 → 封装/解封 DEK | ✅ |
| 4 | 非接收人无法解封（`SM9 decryption MAC check failed`） | ✅ |
| 5 | SM9 签名/验签 + 篡改检测（防抵赖/防信封替换） | ✅ |
| 6 | 端到端串联：封装DEK→SM4加密→解封DEK→SM4解密→还原 | ✅ |

## 选定的国密库：`@lryncloud/crypto`（纯 JS）

调研结论（为何是它）：
- `gmssl-js`（旧 WASM 端口）已于 2025-07 **下架**，不可用。
- `sm-crypto` / `sm-crypto-v2`：只有 SM2/SM3/SM4，**无 SM9**。
- `gmssl-node`：有 SM9，但是 **Node 原生绑定**，进不了浏览器。
- `@lryncloud/crypto`：**唯一**纯 JS（可进浏览器）且支持 SM9 的候选，API 与本系统设计 1:1 对应。

API → 系统角色映射：

| 库 API | 系统中的角色 |
|---|---|
| `sm9CreateMasterKeyPair(masterSecret)` | KGC 初始化 SM9 主密钥（含签名/加密两套主公钥） |
| `sm9DeriveEncryptPrivateKey(identity, masterSecret)` | KGC 按身份**签发**用户加密私钥 |
| `sm9DeriveSignPrivateKey(identity, masterSecret)` | KGC 签发用户签名私钥 |
| `sm9Encrypt(dek, {userId, masterEncryptPublicHex})` | 发送端用**接收人身份**封装 DEK → keyEnvelope |
| `sm9Decrypt(env, {userId, encryptPrivateKeyHex})` | 接收端用自己私钥解封 DEK |
| `sm9Sign / sm9Verify` | 发送方对投递清单签名 / 接收方验签 |
| `sm4EncryptCbc / sm4DecryptCbc` | 文件内容 + 元数据对称加密 |
| `sm3Hex` | 文件/分块摘要、日志哈希链 |

## 关键约束 & 论文需如实说明的点

1. **库成熟度**：`@lryncloud/crypto` v1.0.0、月下载量低。已用国标向量 + 往返 + 负例(MAC 失败) 交叉验证正确性；论文「系统不足/展望」中应注明：生产环境建议替换为经认证的国密实现（如 GmSSL WASM 自编译或硬件密码模块）。
2. **浏览器可移植性**：该库为纯 JS、零依赖，无 Node 专属调用；`poc.mjs` 仅 `node:crypto.randomBytes` 一处，浏览器替换为 `crypto.getRandomValues` 即可。前端工程化后会补一个 HTML 版冒烟测试。
3. **DEK 封装方式**：PoC 采用 `sm9Encrypt` 直接封装 16 字节 DEK（简单可靠）。备选 `sm9KemEncapsulate`（KEM）亦可，后续按需选定，`keyEnvelope.algorithm` 字段保留扩展。
4. **KGC 端实现**：本 PoC 用 JS 同库充当 KGC 做对照。正式 KGC 服务为 Spring Boot(Java)，将通过同一身份格式签发私钥；Java 侧若无等价 SM9 实现，回退方案为「Node 子进程/sidecar 调本库」或「GmSSL 命令行封装」，待 Step 4 落地时定。

## 固定测试数据（供联调复用）

- 身份格式：`user:{tenantId}:{userId}:{email}`
- 示例身份：`user:corp001:10002:bob@example.com` 等
- KGC 主密钥(示例)：`0130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f401`

## 复现

```bash
cd D:\biyesheji\poc-crypto
node poc.mjs
```
