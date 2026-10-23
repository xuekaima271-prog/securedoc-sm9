# deploy —— 一键运行（无 Docker）

## 系统组成（全部已实现）
| 服务 | 端口 | 说明 |
|---|---|---|
| 前端 (Vue3+Vite) | 5173 | 登录/密钥初始化/发送/收件解密/发件箱/管理员/审计/国密自检；**加解密全部在浏览器内** |
| 应用服务器 (Spring Boot) | 8080 | 认证/RBAC/限流/文件盲存储/密钥编排(代理KGC)/管理员/审计SM3哈希链 |
| KGC 密钥中心 (Spring Boot) | 8081 | SM9 主密钥安全存储、身份登记、按身份签发用户私钥、签发审计 |

开发模式用 **H2 内存数据库**（启动自动建表+灌演示数据）+ 本地文件对象存储，**无需安装 MySQL / Docker / MinIO**。

## 一键启动（dev，日常开发/演示）

| 方式 | 操作 |
|---|---|
| **Windows 双击** | 双击 `deploy\启动.bat` |
| PowerShell | `powershell -ExecutionPolicy Bypass -File deploy\start-all.ps1` |
| Git Bash | `bash deploy/start-all.sh` |

启动后浏览器打开 **http://localhost:5173**。

- 应用健康：http://localhost:8080/api/health
- KGC 健康：http://localhost:8081/kgc/health
- H2 控制台：http://localhost:8080/h2-console （JDBC `jdbc:h2:mem:securedoc`，用户 `sa`，空密码）
- 国密自检（浏览器内实跑 SM3/SM4/SM9 + 性能基准）：http://localhost:5173/selftest

演示账号（密码统一 `Demo@123`）：`alice` `bob` `carol`（员工）、`admin`（系统管理员，可新增用户/启停/改角色）、`auditor`（安全审计员，可查审计并验证哈希链）。

## 停止
- 启动窗口按 `Ctrl+C`；或
- `powershell -ExecutionPolicy Bypass -File deploy\stop-all.ps1`（一并停 8080/8081/5173）

## 端到端演示流程（答辩用）
1. `admin` 登录 → 用户管理 → 新增用户（自动生成 SM9 身份并登记到 KGC）
2. 新用户登录 → 密钥初始化（私钥只存本机 IndexedDB）
3. `alice` 登录 → 发送文件（浏览器内 SM4 加密 + SM9 封装密钥）→ 选接收人
4. 接收人登录 → 收件箱 → 解密下载（SM3 校验 + SM9 解封 + SM4 解密）
5. `admin` → 密文记录页：证明服务器/管理员只见密文不可解
6. `auditor` → 审计页：查日志 + 一键验证 SM3 哈希链完整性
7. `auditor` → 安全事件页（§2.2.12）：演示"用 alice 连错 5 次密码 / 用员工号点管理菜单"后，
   暴力破解锁定、越权访问等事件自动出现（连"员工偷看安全事件页"本身也会被记录）

## 自动化验收（另开终端，需三服务在跑）
```bash
cd frontend
node e2e/closed-loop.mjs        # 端到端加密闭环闸门（15 项，含强负例）
node e2e/new-user-journey.mjs   # 新用户完整旅程：创建→KGC登记→签发→收文件→解密（18 项）
node e2e/multi-recipient.mjs    # 多人接收：一份密文·双信封·各自解密（14 项，核心卖点）
node e2e/reissue-journey.mjs    # 换设备重签发：REISSUE 两侧审计一致（8 项）
node --max-old-space-size=4096 e2e/large-file.mjs   # 50MB 大文件分块验收（§18.13）
node e2e/bench.mjs              # 国密性能基准（无需服务）
cd ../backend-app && bash smoke-step5.sh             # 文件服务冒烟（15 项）
cd ../poc-crypto && node sm9-gmt0044-enc-vector.cjs  # GM/T 0044 标准向量对标（无需服务）
```

## 演示期切 MySQL（prod 档，已联调全绿 ✅）
本机已装 **MySQL 8.0.46 绿色版**（`D:\mysql8`，免安装 ZIP，仅监听 127.0.0.1，root 密码 `root`），
双库 `securedoc` / `securedoc_kgc` 已建好灌好，全套 E2E 已在真 MySQL 上跑绿（2026-07-09）。
⚠ 不要再安装 MSI 版 MySQL——其安装/卸载程序会强杀运行中的 mysqld 进程。

1. 启动/停止 MySQL（常驻进程，开机不自启）：
   ```bash
   D:/mysql8/bin/mysqld.exe --defaults-file=D:/mysql8/my.ini --console     # 启动（保持窗口）
   D:/mysql8/bin/mysqladmin.exe -h127.0.0.1 -uroot -proot shutdown          # 停止
   ```
2. （仅需重置数据时）重灌双库（**必须 utf8mb4**，见 `database/mysql_init.sql` 内注释）：
   ```bash
   M="D:/mysql8/bin/mysql.exe -h127.0.0.1 -uroot -proot --default-character-set=utf8mb4"
   $M < database/mysql_init.sql
   $M securedoc     < database/schema.sql && $M securedoc     < database/init_data.sql
   $M securedoc     -e "ALTER TABLE users AUTO_INCREMENT=10006;"
   $M securedoc_kgc < database/schema.sql && $M securedoc_kgc < database/init_data.sql
   $M securedoc_kgc -e "ALTER TABLE users AUTO_INCREMENT=10006;"
   ```
3. 以 prod 档启动（日志已降级 INFO、H2 console 关闭，见 SEC-4；KGC 用独立库
   `securedoc_kgc`——共库会引发 createUser 分布式死锁 + KGC 无链审计行破坏哈希链，见账本 Step11）：
   ```bash
   cd backend-app  && DB_USER=root DB_PASSWORD=root ./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
   cd kgc-service  && DB_USER=root DB_PASSWORD=root ./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
   ```
## 对象存储切 MinIO（可选，已实现并活体验证 ✅）
默认本地文件系统（零安装）。MinIO 版 `MinioStorage` 已实现（`storage.type` 一键切换，
E2E 闭环 15/15 + 50MB 大文件 6/6 已在 MinIO 上跑绿，密文对象落 `deploy/minio/data/securedoc` 桶）：
```bash
# 1. 启动 MinIO（minio.exe 已在 deploy/minio/，已 gitignore）
cd deploy/minio && ./minio.exe server ./data --address :9000 --console-address :9001
# 2. 后端以 MinIO 模式启动（默认账号 minioadmin/minioadmin，仅本机演示；生产改环境变量）
cd backend-app && SECUREDOC_STORAGE_TYPE=minio DB_USER=root DB_PASSWORD=root \
  ./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
# 控制台 http://localhost:9001 可视化查看密文对象（证明服务器只存密文）
```

## 环境要求
- JDK 21+（`java -version`）
- Node 18+（`node -v`），首次启动前端会自动 `npm install`
- 无需全局 Maven（用各服务内置 `mvnw`）
