# Step 1 国密能力 PoC —— 结论

对应设计文档《项目目录与落地路线图》§18.11「第一步：国密能力 PoC」。

## ⚠ 后续修正（2026-10-23，依据 `SM9-GATE-RESULT.md` 闸门复核与《密码专项评审》）

本文件是 Step 1 当时的历史结论，其中数处已被后续验证推翻或更新，**只读本文件会得出错误选型**，务必结合本节：

1. **选型作废**：下文「选定的国密库 `@lryncloud/crypto`」整节结论已被闸门复核证伪——该库的 SM9 是标量模拟（群点被表示为单个标量、"双线性对"是标量乘指数），并非 GM/T 0044 真 SM9，不可能命中国标向量、无实际安全性。验证表中第 3/4/5 项在该库上跑出的"通过"，只证明了 API 层面的代数同态（往返自洽、错误身份失败），**不构成 SM9 正确性证据**。
2. **现行选型（生产实际）**：浏览器端基于 `guanzhi/GmSSL-JS` 的真曲线实现（完整 Fp/Fp2/Fp4/Fp12 塔式扩域 + R-ate 配对，实测命中 GM/T 0044 标准向量）自补 SM9 IBE 高层——见 `frontend/src/crypto/sm9-ibe.js` 与 `frontend/src/crypto/vendor/gmssl-src.js`；Java KGC 自研 `Sm9Core`（主密钥生成与私钥提取只需曲线点乘、无需配对）。两端互通已通过闸门验收（`SM9-GATE-RESULT.md` §九：JS IBE 往返 3/3、Java↔JS 逐字节互通 4/4）。
3. **计数更正**：正文原称"7/7 全部通过"系笔误，验证表实际 6 项，已更正为 6/6。
4. **签名防线未进生产**：验证项 5 与 API 映射表中的 `sm9Sign/sm9Verify` 仅为 PoC 层验证；生产未采用 SM9 投递清单签名（信封只有 wrappedKey + 无钥 keyDigest，发送者真实性依赖服务端 DB 记录），见《密码专项评审》中-密5。不要据本文件认为该防线已落地。
5. 「关键约束」第 4 点预留的 Java 回退方案（Node sidecar / GmSSL 命令行封装）**未启用**——Java 侧自研实现已落地并通过互通验证；第 1 点关于 `@lryncloud/crypto` 成熟度的说明随选型作废，仅作历史记录。

## 结论：国密混合加密主线可落地 ✅

用真实代码（`poc.mjs`，可 `node poc.mjs` 复现）验证了系统密码主线，6/6 全部通过（计数经 2026-10-23 修正，见文首修正第 3 条；其中 SM9 相关项的证据效力见修正第 1 条）。

| # | 验证项 | 结果 |
|---|---|---|
| 1 | SM3("abc") 命中 GB/T 32905-2016 国标向量 | ✅ |
| 2 | SM4-CBC 文件加解密往返一致（文件密文层） | ✅ |
| 3 | SM9：KGC 主密钥 → 按身份签发私钥 → 封装/解封 DEK | ✅ |
| 4 | 非接收人无法解封（`SM9 decryption MAC check failed`） | ✅ |
| 5 | SM9 签名/验签 + 篡改检测（防抵赖/防信封替换） | ✅ |
| 6 | 端到端串联：封装DEK→SM4加密→解封DEK→SM4解密→还原 | ✅ |

## 选定的国密库：`@lryncloud/crypto`（纯 JS）

> ⚠ **本节已被推翻（2026-10-23）**：该库的 SM9 经闸门复核证实为标量模拟假实现，本节仅保留为 Step 1 当时的调研记录。现行选型见文首修正第 2 条，不要据本节做选型判断。

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
| `sm9Sign / sm9Verify` | 发送方对投递清单签名 / 接收方验签（⚠ 仅 PoC 验证，生产未采用，见文首修正第 4 条） |
| `sm4EncryptCbc / sm4DecryptCbc` | 文件内容 + 元数据对称加密 |
| `sm3Hex` | 文件/分块摘要、日志哈希链 |

## 关键约束 & 论文需如实说明的点

1. **库成熟度**（针对已作废的 `@lryncloud/crypto` 选型，历史记录）：`@lryncloud/crypto` v1.0.0、月下载量低。已用国标向量 + 往返 + 负例(MAC 失败) 交叉验证正确性；论文「系统不足/展望」中应注明：生产环境建议替换为经认证的国密实现（如 GmSSL WASM 自编译或硬件密码模块）。
2. **浏览器可移植性**：该库为纯 JS、零依赖，无 Node 专属调用；`poc.mjs` 仅 `node:crypto.randomBytes` 一处，浏览器替换为 `crypto.getRandomValues` 即可。前端工程化后会补一个 HTML 版冒烟测试。
3. **DEK 封装方式**：PoC 采用 `sm9Encrypt` 直接封装 16 字节 DEK（简单可靠）。备选 `sm9KemEncapsulate`（KEM）亦可，后续按需选定，`keyEnvelope.algorithm` 字段保留扩展。
4. **KGC 端实现**：本 PoC 用 JS 同库充当 KGC 做对照。正式 KGC 服务为 Spring Boot(Java)，将通过同一身份格式签发私钥；Java 侧若无等价 SM9 实现，回退方案为「Node 子进程/sidecar 调本库」或「GmSSL 命令行封装」，待 Step 4 落地时定。（2026-10-23 注：回退方案未启用——Step 4 已以 Java 自研 `Sm9Core` 落地并通过与浏览器端的逐字节互通验证，见文首修正第 2、5 条。）

## 固定测试数据（供联调复用）

- 身份格式：`user:{tenantId}:{userId}:{email}`
- 示例身份：`user:corp001:10002:bob@example.com` 等
- KGC 主密钥(示例)：`0130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f401`

## 复现

```bash
cd D:\biyesheji\poc-crypto
node poc.mjs
```
