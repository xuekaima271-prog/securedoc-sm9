# SM9 闸门结论（进 Step4 前的关键验证）

对应账本 SM9-1 / SM9-2。**结论：当前选用的浏览器 SM9 库是模拟实现，Path B 被证伪，需重新决策密码方案。**

## 一、关键发现：`@lryncloud/crypto` 的 SM9 是模拟，不是真 SM9

源码证据（`node_modules/@lryncloud/crypto/src/sm9/`）：

- `groups.cjs`：椭圆曲线群点被表示成**单个标量** `{group, scalar}`，`pointMul` 就是 `scalar * k mod n`（标量乘，非 EC 点乘）。文件头注释自称"简化"。
- `pairing.cjs`：`sm9Pairing(p,q) = g^(p.scalar * q.scalar)`，注释"简化 SM9 双线性对"。即用**标量乘法冒充 R-ate 配对**。

真 SM9：群点是 BN256 曲线 `(x,y)` 坐标，配对是几十毫秒级的 R-ate 运算。该库只保留了代数同态性质 `e([a]P,[b]Q)=e(P,Q)^{ab}`，所以**功能往返/错误身份失败都"看起来对"**（骗过了 Step1 功能测试），但：

| 影响 | 结论 |
|---|---|
| SM9-1 国标符合性 | **必然 FAIL**（标量模拟不可能命中 GM/T 0044 向量；亦解释"亚毫秒"性能） |
| SM9-2 Path B（Java↔JS 互通） | **物理不可能**：真 Java GmSSL 做真曲线配对，无法与标量模拟互通 |
| 实际安全性 | **无**：公钥=标量、密钥派生=模运算，可被推算；不能用于真实安全声明 |

## 二、真 SM9 的可得性（调研）

| 实现 | 真SM9? | 运行环境 | 能否浏览器端 |
|---|---|---|---|
| `@lryncloud/crypto` | ❌模拟 | JS | （是但假）|
| `gmssl-node`（GmSSL 作者 guanzhi）| ✅真 | Node 原生绑定 | ❌ 仅服务端 |
| `GmSSL-Java` | ✅真 | JNI 原生 | ❌ 仅服务端 |
| `mcl-wasm`（Herumi）| 真配对原语 | JS/WASM 浏览器✅ | 需**自实现** SM9 层 |
| 浏览器现成真 SM9 | — | — | ❌ 未发现 |

矛盾：端到端要求 SM9 解封/解密在**浏览器**完成；而现成的真 SM9 只有**服务端**版本。

## 三、可选方案（待用户决策）

| 选项 | 做法 | 真SM9 | 浏览器 | 工作量/风险 | 论文影响 |
|---|---|---|---|---|---|
| **1 真SM9进浏览器** | GmSSL 编 WASM 暴露 SM9，或在 mcl-wasm 上自实现 SM9 层（按 GM/T 0044）| ✅ | 需自建 | 高/高（数天，需对国标向量）| **完全保留 SM9**，且真 Java KGC 互通成立（满足你要的 Java 路）|
| **2 改 SM2 封装** | SM4 + **SM2** 混合（`sm-crypto` 浏览器现成、真 SM2）| SM2(非SM9) | ✅现成 | 低/低 | 主线由"SM9 身份基"→"SM2 公钥"，KGC 改为公钥/证书管理，需改设计文档较多 |
| 3 保留模拟 | 继续用假库 | ❌ | - | - | ✗ 学术诚信问题，答辩风险，不采纳 |

## 四、建议
本系统的核心创新点就是 **SM9 身份基**；若放弃 SM9，论文新颖性受损。故建议优先 **选项 1**，但先做**严格 timeboxed 可行性 spike**：确认能否取得/构建可用的真 SM9 WASM（先查 GmSSL-JS 源码是否可编、或 SM9-on-mcl 是否可控），spike 不过再退选项 2。
选项 1 同时满足你坚持的"真 Java KGC"——因为届时浏览器与 Java 都是 GM/T 0044 真实现，可互通。

## 五、Option 1 可行性 spike（S1）结果：真 SM9 进浏览器 —— 三路全堵，止损

| 路线 | 结果（实测） |
|---|---|
| `mcl-wasm` 自实现 SM9 | ❌ mcl 仅 BN254/BN381/BN462/BN_SNARK1/BLS12_381…，**无 SM9 曲线**；预编译 WASM 不开放自定义 BN 参数 |
| GmSSL → WASM | ❌ 本机无 `emcc`(Emscripten)；npm 无任何现成 GmSSL WASM 包(gmssl/gmssljs/gmssl-wasm/sm9js/gm-sm9 均无) |
| `gmssl-node`(真SM9原生) | ❌ node-gyp 编译失败(缺 MSVC)；且 Node 端、进不了浏览器 |
| 纯 JS 真 SM9 | ❌ 不存在 |

**结论：当前环境+毕设周期内，"真 SM9 在浏览器端运行"不可行。Option 1 止损。**

## 六、最终建议：转 Option 2（SM4 + SM2 混合），最小改动保住系统
- 浏览器端用 **`sm-crypto` 的真 SM2**（成熟、现成、真国密）封装 DEK，替换 SM9 这一步。
- **架构几乎不动**：SM4 文件加密、盲存储、`file_recipients`+密钥信封、KGC、RBAC、审计、端到端——全部保留。
  - KGC 由"按身份派生 SM9 私钥"→"为用户签发 SM2 密钥对"（流程几乎一致，仍是独立可信组件，甚至可签发 SM2 证书→更贴近 PKI 故事）。
  - `key_envelope` 改存 SM2 加密后的 DEK。
- 论文主线由"SM9 身份基"→"SM2 公钥混合加密"，是**真实、完整、可答辩**的国密 E2E 系统；SM9 放入"相关工作/未来工作"，并如实说明浏览器端真 SM9 库缺位的工程结论（这本身就是有价值的工程发现）。

## 七、🟢 翻盘：找到真 SM9（推翻第五/六节的"Option 1 不可行"）

`guanzhi/GmSSL-JS`（GmSSL 作者，Apache-2.0，纯 JS，`gmssljs/sm9.js` 28KB）是**真 SM9**：
- 完整塔式扩域 Fp/Fp2/Fp4/Fp12（mul/inv/frobenius）、G1 点 + G2 twist 点运算、Miller 循环、final_exponent、R-ate 配对 `sm9_pairing`。
- **实测**：`node gmssljs/sm9.js` → `test pairing: true`，即 `e(Ppub-s,P1)` 命中 GM/T 0044 标准向量。配对**符合国标**。
- 纯 JS + `window.crypto` 随机源 → **浏览器可用**。

**缺口**：该库到配对为止，**没有高层 IBE 层**（encrypt/decrypt/sign/verify/keygen/extract）。需按 GM/T 0044 在其配对/曲线之上补这层，并用国标 IBE 向量校验。

关键减负：**KGC 的密钥签发不需要配对**（master keygen = `[ks]P2`；私钥提取 = `[t2]P1`，只需标量 + G1/G2 点乘）。故：
- 浏览器(JS)：完整 IBE 加解密（用本库配对）。
- Java KGC：只需 SM9 曲线点乘做 keygen/extract（无配对，Java 侧好实现），输出与 JS 一致的标准编码 → 互通可成立。

## 八、最终方案（Option 1 可行）
1. 浏览器：基于 `guanzhi/GmSSL-JS` 的配对/曲线，补 SM9 IBE 加解密层，**国标向量校验**。
2. Java KGC：实现 SM9 master keygen + 按身份 extract 私钥（无配对），CSPRNG 主密钥（SM9-5）。
3. 互通：两端均 GM/T 0044 标准编码，对同一国标向量校验 → Java↔JS 互通。

## 九、最终验收：闸门清零 ✅
- `sm9-ibe-test.cjs` **3/3**：JS 真 SM9 IBE 封装/解封 DEK 往返、非接收人失败、篡改失败。
- `sm9-interop.cjs` **4/4**：原生 Java KGC(`java/Sm9Kgc.java`，BigInteger 移植 G1/G2 点乘，无配对，SecureRandom 主密钥) 产出的 Ppub_e/de 与 JS **逐字节一致**，且 Java 密钥跑 JS-IBE 封装解封成功（双向）。
- **结论**：真 SM9（GM/T 0044 配对合标准）+ 原生 Java KGC + 浏览器 JS IBE = **端到端互通可行**。用户坚持的"真 SM9 + Java KGC"成立。
- 资产：`gmssljs/`(guanzhi 库)、`sm9-ibe-test.cjs`、`java/Sm9Kgc.java`、`sm9-interop.cjs`。

## 十、对项目的影响
- Step4(KGC) 按**真 SM9 + 原生 Java** 推进。正式 KGC 服务需补 Java SM3(做 H1) + 主密钥安全存储。
- 后端基础（登录/RBAC/限流/审计）不受影响，与密码方案解耦。
- SM9-10（对标加密密文向量）作为论文增强项，配对核心已对标，往返+互通已证。
