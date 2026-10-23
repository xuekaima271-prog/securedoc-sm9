# 04 KGC 服务设计（SM9 密钥生成中心）

> 对应路线图「第四步：KGC 服务」、设计文档 §2.4 / §2.6 / §18.6.4 / §18.9.2。
> 本服务把 PoC 阶段实证的真 SM9 算法升级为**独立、可签发、可审计、主密钥安全存储**的生产形态雏形。

## 1. 定位与边界

- **独立 Spring Boot 服务**，端口 `:8081`，与应用服务器(:8080)逻辑分离部署（§2.6 安全边界）。
- 职责：管理 SM9 加密主密钥、按用户身份**签发/重新签发** SM9 用户私钥、记录签发审计。
- 主私钥 `ke` **只存在于 KGC 内部**（加密落盘），不出服务；对外只暴露主公钥 `Ppub_e` 与「按身份提取私钥」能力。
- 与应用服务器共享数据库（dev=各自独立 H2 内存库；prod=同一 MySQL `securedoc`）：KGC 写 `kgc_private_key_issues`、读/更新 `user_keys`、写 `audit_logs`。

## 2. 算法（原生 Java，无配对）

逐字移植自 `guanzhi/GmSSL-JS`，已在 PoC 实证与浏览器 JS 逐字节一致（见 `poc-crypto/sm9-interop.cjs`）。

- 主公钥：`Ppub_e = [ke]·P1`（G1），序列化 64 字节 = `x(32)||y(32)`。
- 用户私钥：`h1 = H1(ID, hid=0x03)`；`t1 = (h1+ke) mod N`；`t2 = ke·t1⁻¹ mod N`；`de = [t2]·P2`（G2），序列化 128 字节 = `x0||x1||y0||y1`（各 32 字节）。
- `H1`：`funcH(0x01, ID||hid, N)`，用 **Java 原生 SM3**（`crypto/Sm3.java`，GB/T 32905）计数扩展实现 —— 相对 PoC 的关键升级（PoC 的 H1 是从 JS 传参）。
- keygen/extract **只用标量点乘**，不需要配对（配对只在浏览器加解密侧用）。

**字节级正确性**：`Sm9CoreTest` 用固定 `ke` + Bob 身份，断言 Java 自算的 `h1/Ppub_e/de` 与 guanzhi JS 真值逐字节一致（基准由 `poc-crypto/sm9-expected-values.cjs` 生成）。

## 3. 主密钥安全存储（SM9-5）

`Sm9MasterKeyService` + `crypto/MasterKeyCipher`：

- 启动 load-or-generate：无 keystore → `SecureRandom` 生成 `ke` → 加密落盘 `data/sm9-master.key`；有则解封恢复。
- 落盘加密：口令 →`PBKDF2WithHmacSHA256(210000 次)`→ 256bit KEK →`AES-256-GCM`→ 主私钥密文。每次新随机 `salt(16)+iv(12)`，GCM 自带完整性校验（口令错/被篡改→解封抛异常）。
- 口令来自配置 `kgc.master-key.passphrase`（环境变量 `KGC_MASTER_PASSPHRASE`）；**缺口令安全报错**，不裸奔。
- `data/` 已加入 `.gitignore`，主密钥密文绝不入库。

## 4. 接口（§2.4 / §18.9.2）

| 方法 | 路径 | 说明 | 鉴权 |
|---|---|---|---|
| POST | `/kgc/sm9/issue-private-key` | 首次签发用户私钥 | 需 `X-KGC-Token` |
| POST | `/kgc/sm9/reissue-private-key` | 重新签发（换设备/恢复） | 需 `X-KGC-Token` |
| GET | `/kgc/sm9/issues` | 分页查询签发记录（审计页） | 需 `X-KGC-Token` |
| GET | `/kgc/sm9/master-public-key` | 主公钥 Ppub_e（公开） | 放行 |
| GET | `/kgc/sm9/identity/{userId}` | 查用户 SM9 身份 | 放行 |
| GET | `/kgc/health` | 健康检查 | 放行 |

- 签发响应（§18.6.4）：`{issueId, userId, identity, privateKeyPackage(Base64 de), issuedAt}`，统一包在 `ApiResponse{success,code,message,data}` 内。
- 签发前校验：身份格式 `user:{tenantId}:{userId}:{email}`（`IDENTITY_INVALID`）；用户存在（`USER_NOT_FOUND`）；请求身份与 `user_keys.sm9_identity` 绑定一致（`IDENTITY_MISMATCH`）——杜绝为伪造身份发钥。
- 签发后：写 `kgc_private_key_issues`（FIRST/REISSUE，RECORDED）；推进 `user_keys.key_status`→ISSUED/REISSUED；写 `audit_logs`（KGC_ISSUE/KGC_REISSUE，best-effort）。

## 5. 鉴权（MVP）

`KgcTokenFilter`：签发类/审计类接口要求 `X-KGC-Token` 与配置 `kgc.service-token` **常量时间**比较一致，否则 401 `KGC_UNAUTHORIZED`。
**生产升级方向**（论文标注）：KGC_ADMIN 独立权限 + mTLS 双向认证（§2.6）。本 token 方案是可运行的最小可信边界。

## 6. 🔴 重大发现：修复 guanzhi/GmSSL-JS 的两处缺陷（端到端实证暴露）

在 Step9「真服务 ↔ 浏览器 JS 端到端互通」的**负例**（对的身份串 + 错的私钥应解密失败）中，发现并定位了**两个互相掩盖的 bug**，导致 PoC 阶段的「真 SM9 IBE 3/3、互通 4/4」其实是**假阳性**：

1. **`sm3` 多分块 bug（库 bug）**：`sm3_compress_blocks` 的分块循环未推进读偏移 `offset`，导致长消息（≥2 整块）只算首块+缓冲尾块，**中间块被忽略**。已修（每块 `offset += 64`）。
   - 影响：IBE 的 KDF 输入 `Z = C1(64)||w(384)||ID` 中，配对值 `w` 恰落在被忽略的中间块 → K1/MAC 与私钥（经 `w` 体现）**无关** → 任何持合法私钥者只要知道（公开的）身份串即可解密 = 机密性被破坏。
2. **`point_mul` 仿射基点要求（用法 bug）**：IBE 封装里 `point_mul(C1, r, QB)` 的 `QB` 是 `point_add` 的 Jacobian 输出，而 `point_mul` 要求**仿射基点** → `C1` 算错 → `e(de,C1) ≠ g^r`。已修（`point_mul` 前 `QB` 转仿射）。

**定位方法**：固定向量二分（sm3 改不同位置看摘要是否变）+ 双线性/`fp12_pow`/`point_mul` 隔离探针（全仿射输入下逐一验证）。
**修复后**：`sm9-ibe-test`（强负例：对身份串+错私钥→失败）3/3、`sm9-interop` 4/4、`kgc-service-interop`（闸门）**7/7**，均**真实**通过，IBE 现在**真正按私钥绑定身份**。
Java 侧 `Sm3` 本身正确（有正确的分块循环），`Sm3Test` 已加 128/200 字节多分块用例与修复后的 guanzhi 交叉核对锁死。

## 7. 测试与验证

- `kgc-service` 单元/集成测试 **31 全绿**：SM3(国标+多分块) / SM9 核心字节级对标 / 主密钥密封往返+口令错/缺失 / 主密钥生命周期 / 签发 Mapper / 签发接口(往返+404+身份不匹配+缺字段) / 主公钥+身份+重签发+查询 / 鉴权(401/200)+身份格式。
- `backend-app` 30 测试无回归。
- 端到端闸门：`node poc-crypto/kgc-service-interop.cjs` → 7/7（取主公钥→签发→封装→解封还原 DEK + 非接收人私钥失败 + 篡改失败）。
- 一键启动：`deploy/start-all.ps1`（KGC 独立窗口 + 应用前台），`stop-all.ps1` 同停 8080/8081。

## 8. 设计文档符合性（§3 国密混合加密 / §2.4 / §2.6 / §18）

- ✅ KGC 独立服务、按身份签发、不用 SM9 直接加大文件（只签发私钥供浏览器封 DEK）。
- ✅ 主密钥安全存储 + CSPRNG 生成（SM9-5）。
- ✅ 签发审计留痕（kgc_private_key_issues + audit_logs）。
- ✅ 接口/响应格式符合 §2.4 / §18.6.4 / §18.9.2。
- ✅ 真 SM9（R-ate 配对合标准）、身份绑定（修复后真正生效）、防篡改。
- 诚实标注：MVP 鉴权用服务令牌（生产升级 KGC_ADMIN+mTLS）；IBE 密文对标 GM/T0044 标准向量为后续增强（SM9-10）。
