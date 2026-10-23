-- =============================================================================
-- 企业级端到端加密文档投递系统 —— 核心表结构 schema.sql
-- 对应设计文档 §5 第五阶段(数据库设计) / §18.8(数据库实现前补充要求)
--
-- 兼容性说明（重要）：
--   本文件刻意写成「可移植 SQL」，同时可在以下两种环境直接执行：
--     · 开发期：H2 数据库（MODE=MySQL，嵌入式，零安装）
--     · 演示期：MySQL 8（默认即 InnoDB + utf8mb4，无需显式声明）
--   为此本文件遵守以下约束：
--     · 不使用 ENGINE=/CHARSET= 子句（MySQL 8 默认已是 InnoDB+utf8mb4；H2 不识别）
--     · 不使用 ON UPDATE CURRENT_TIMESTAMP（H2 不支持；updated_at 由应用层维护）
--     · JSON 文档统一用 TEXT 存储（前端传 JSON 字符串），便于 MyBatis 直接映射 String
--     · 字段说明用 -- 行注释（通用），不用 MySQL 内联 COMMENT 子句
--   演示期在 MySQL 上建库（utf8mb4）：
--     CREATE DATABASE securedoc DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
--
--   ⚠ 本文件为 UTF-8 编码，加载时务必按 UTF-8 读取，否则中文(姓名/角色名/注释)会乱码：
--     · Spring Boot : spring.sql.init.encoding=UTF-8
--     · MySQL CLI   : mysql --default-character-set=utf8mb4 ... < schema.sql
--     · H2 RUNSCRIPT: RUNSCRIPT FROM '.../schema.sql' CHARSET 'UTF-8'
--   （已用 H2 实测：UTF-8 加载后中文入库/出库完好）
--
-- 安全红线（数据库绝不保存）：文件明文 / 明文文件名 / SM4 文件密钥明文 / 用户 SM9 私钥明文
-- =============================================================================

-- ---- 按外键依赖逆序清理，保证可重复执行 ----
DROP TABLE IF EXISTS security_events;
DROP TABLE IF EXISTS file_recipients;
DROP TABLE IF EXISTS file_chunks;
DROP TABLE IF EXISTS files;
DROP TABLE IF EXISTS kgc_private_key_issues;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;


-- =============================================================================
-- roles —— 角色表（RBAC）
-- =============================================================================
CREATE TABLE roles (
    id          BIGINT       NOT NULL AUTO_INCREMENT,
    role_code   VARCHAR(32)  NOT NULL,                 -- 角色编码：EMPLOYEE/SYS_ADMIN/SUPER_ADMIN/SECURITY_AUDITOR/DEPT_ADMIN/KGC_ADMIN
    role_name   VARCHAR(64)  NOT NULL,                 -- 角色名称（展示用）
    description VARCHAR(255),                          -- 角色说明
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_roles_code UNIQUE (role_code)
);


-- =============================================================================
-- users —— 用户账号表
-- 安全：password_hash 只存 BCrypt 哈希，绝不存明文密码
-- =============================================================================
CREATE TABLE users (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    username      VARCHAR(64)  NOT NULL,               -- 登录账号（唯一）
    password_hash VARCHAR(100) NOT NULL,               -- BCrypt 哈希（$2a/$2b$，约60字符）
    real_name     VARCHAR(64),                         -- 姓名
    email         VARCHAR(128),                        -- 邮箱（用于 SM9 身份标识可读部分）
    department_id BIGINT,                               -- 部门ID（逻辑外键；departments 表 MVP 暂缓）
    status        VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE', -- ACTIVE/DISABLED/LOCKED
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP, -- 由应用层更新
    PRIMARY KEY (id),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT ck_users_status CHECK (status IN ('ACTIVE','DISABLED','LOCKED'))
);
CREATE INDEX idx_users_email ON users (email);


-- =============================================================================
-- user_roles —— 用户-角色关联表（多对多）
-- =============================================================================
CREATE TABLE user_roles (
    id      BIGINT NOT NULL AUTO_INCREMENT,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT uk_user_roles UNIQUE (user_id, role_id),
    CONSTRAINT fk_ur_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE RESTRICT
);


-- =============================================================================
-- user_keys —— 用户 SM9 身份标识与密钥状态
-- 安全：只存身份标识与状态，绝不存 SM9 私钥明文（私钥在浏览器 IndexedDB）
-- =============================================================================
CREATE TABLE user_keys (
    id              BIGINT       NOT NULL AUTO_INCREMENT,
    user_id         BIGINT       NOT NULL,             -- 唯一：一个用户一条
    sm9_identity    VARCHAR(255) NOT NULL,             -- 唯一：user:{tenantId}:{userId}:{email}
    key_status      VARCHAR(16)  NOT NULL DEFAULT 'UNINITIALIZED', -- UNINITIALIZED/ISSUED/REISSUED/REVOKED
    device_bound    BOOLEAN      NOT NULL DEFAULT FALSE,-- 是否已有设备绑定本地私钥
    last_issue_time DATETIME,                           -- 最近一次 KGC 签发时间
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_user_keys_user     UNIQUE (user_id),
    CONSTRAINT uk_user_keys_identity UNIQUE (sm9_identity),
    CONSTRAINT ck_user_keys_status CHECK (key_status IN ('UNINITIALIZED','ISSUED','REISSUED','REVOKED')),
    CONSTRAINT fk_uk_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);


-- =============================================================================
-- kgc_private_key_issues —— KGC 私钥签发审计记录
-- 这是 SM9 在系统中落地的关键证据（答辩可展示）。审计独立，不设外键。
-- =============================================================================
CREATE TABLE kgc_private_key_issues (
    id                 VARCHAR(36)  NOT NULL,          -- 签发记录ID（UUID）
    user_id            BIGINT       NOT NULL,
    sm9_identity       VARCHAR(255) NOT NULL,
    issue_type         VARCHAR(16)  NOT NULL DEFAULT 'FIRST', -- FIRST/REISSUE
    device_fingerprint VARCHAR(255),                  -- 浏览器设备指纹
    reason             VARCHAR(255),                  -- 签发原因（如换设备）
    operator_id        BIGINT,                        -- 操作人（自助签发时即用户本人）
    client_ip          VARCHAR(45),                   -- 请求IP（兼容IPv6）
    audit_status       VARCHAR(16)  NOT NULL DEFAULT 'RECORDED', -- RECORDED/REVIEWED/REJECTED
    issued_at          DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_kgc_issue_type   CHECK (issue_type IN ('FIRST','REISSUE')),
    CONSTRAINT ck_kgc_audit_status CHECK (audit_status IN ('RECORDED','REVIEWED','REJECTED'))
);
CREATE INDEX idx_kgc_user     ON kgc_private_key_issues (user_id);
CREATE INDEX idx_kgc_issued_at ON kgc_private_key_issues (issued_at);


-- =============================================================================
-- files —— 文件投递主记录
-- 安全：encrypted_metadata 是 SM4 加密后的元数据（含密文文件名），服务端不存明文文件名
-- =============================================================================
CREATE TABLE files (
    id                   VARCHAR(36) NOT NULL,         -- 文件ID（UUID）
    sender_id            BIGINT      NOT NULL,         -- 发送人
    encrypted_metadata   TEXT        NOT NULL,         -- JSON: {algorithm,mode,iv,ciphertext,digest} 加密后的文件名/MIME/备注
    ciphertext_root_path VARCHAR(255),                 -- 对象存储根路径 encrypted-files/{fileId}
    total_size           BIGINT      NOT NULL DEFAULT 0,-- 密文总大小(字节)
    chunk_size           INT         NOT NULL DEFAULT 0,-- 分块大小(字节)
    chunk_count          INT         NOT NULL DEFAULT 0,-- 分块数量
    status               VARCHAR(16) NOT NULL DEFAULT 'INIT', -- INIT/UPLOADING/AVAILABLE/FAILED/DELETED
    created_at           DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT ck_files_status CHECK (status IN ('INIT','UPLOADING','AVAILABLE','FAILED','DELETED')),
    CONSTRAINT fk_files_sender FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE RESTRICT
);
CREATE INDEX idx_files_sender  ON files (sender_id);
CREATE INDEX idx_files_status  ON files (status);
CREATE INDEX idx_files_created ON files (created_at);


-- =============================================================================
-- file_chunks —— 文件密文分块记录
-- 删除文件时级联删除其分块
-- =============================================================================
CREATE TABLE file_chunks (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    file_id       VARCHAR(36)  NOT NULL,
    chunk_index   INT          NOT NULL,               -- 分块序号(0起)
    object_key    VARCHAR(255) NOT NULL,               -- 对象存储键 encrypted-files/{fileId}/chunk-{index}.bin
    chunk_size    INT          NOT NULL DEFAULT 0,      -- 该块密文大小
    sm3_digest    VARCHAR(128) NOT NULL,               -- 密文分块 SM3 摘要(base64)，下载时校验防篡改
    iv_nonce      VARCHAR(64),                          -- 该块 IV/Nonce(base64)
    auth_tag      VARCHAR(64),                          -- 认证标签(若采用 SM4-GCM 等 AEAD)
    upload_status VARCHAR(16)  NOT NULL DEFAULT 'PENDING', -- PENDING/UPLOADED/FAILED
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_chunk_file_index UNIQUE (file_id, chunk_index),
    CONSTRAINT ck_chunk_status CHECK (upload_status IN ('PENDING','UPLOADED','FAILED')),
    CONSTRAINT fk_chunk_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
);


-- =============================================================================
-- file_recipients —— 文件接收人与 SM9 密钥信封（多人接收核心表）
-- 一份密文只存一份，但每个接收人有独立密钥信封；接收人只能读自己的信封
-- 安全：key_envelope 是 SM9 封装后的 SM4 文件密钥，服务端无法解封
-- =============================================================================
CREATE TABLE file_recipients (
    id                 BIGINT       NOT NULL AUTO_INCREMENT,
    file_id            VARCHAR(36)  NOT NULL,
    recipient_id       BIGINT       NOT NULL,
    recipient_identity VARCHAR(255) NOT NULL,          -- 接收人 SM9 身份标识
    key_envelope       TEXT         NOT NULL,          -- JSON: {algorithm,wrappedKey,keyDigest} SM9 封装的 DEK
    receive_status     VARCHAR(16)  NOT NULL DEFAULT 'PENDING', -- PENDING/READ
    download_status    VARCHAR(16)  NOT NULL DEFAULT 'NONE',    -- NONE/DOWNLOADED/FAILED
    downloaded_at      DATETIME,
    created_at         DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_recipient_file_user UNIQUE (file_id, recipient_id),
    CONSTRAINT ck_recv_status CHECK (receive_status  IN ('PENDING','READ')),
    CONSTRAINT ck_dl_status   CHECK (download_status IN ('NONE','DOWNLOADED','FAILED')),
    CONSTRAINT fk_recip_file FOREIGN KEY (file_id)      REFERENCES files (id) ON DELETE CASCADE,
    CONSTRAINT fk_recip_user FOREIGN KEY (recipient_id) REFERENCES users (id) ON DELETE RESTRICT
);
CREATE INDEX idx_recipients_recipient ON file_recipients (recipient_id);


-- =============================================================================
-- audit_logs —— 审计日志（支持 SM3 哈希链防篡改说明）
-- 审计独立留存，不设外键（actor 可为空/系统，且需在用户删除后仍可追溯）
-- =============================================================================
CREATE TABLE audit_logs (
    id            BIGINT       NOT NULL AUTO_INCREMENT,
    actor_id      BIGINT,                               -- 操作人(可空=系统行为)
    action        VARCHAR(64)  NOT NULL,               -- LOGIN/LOGOUT/LOGIN_FAIL/FILE_UPLOAD/FILE_DOWNLOAD/KGC_ISSUE...
    resource_type VARCHAR(32),                          -- FILE/USER/KEY...
    resource_id   VARCHAR(64),
    client_ip     VARCHAR(45),
    user_agent    VARCHAR(255),
    detail        TEXT,                                 -- 详情(JSON/文本)
    previous_hash VARCHAR(128),                         -- 上一条日志哈希(哈希链衔接，逐字存上一条 current_hash)
    current_hash  VARCHAR(128),                         -- 当前日志哈希：v2="v2$"+Base64(HMAC-SM3(服务端密钥, previous_hash || log_content))；无前缀=v1 存量无钥 SM3(M-3)
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE INDEX idx_audit_created ON audit_logs (created_at);
CREATE INDEX idx_audit_actor   ON audit_logs (actor_id);
CREATE INDEX idx_audit_action  ON audit_logs (action);


-- =============================================================================
-- login_attempts —— 登录失败聚合与限流（每「账号×来源IP」一行，M-5）
-- MVP 无 Redis：登录限流/锁定由本表 + 应用内缓存实现
-- M-5：锁定维度由账号全局改为 (username, client_ip) 组合——攻击者轮换 IP 只能锁住
--   自己的来源，无法再把账号（含管理员）对所有来源全局锁死；代价见 LoginThrottleService 类注释。
-- =============================================================================
CREATE TABLE login_attempts (
    id             BIGINT      NOT NULL AUTO_INCREMENT,
    username       VARCHAR(64) NOT NULL,               -- 账号（与 client_ip 组合唯一）
    client_ip      VARCHAR(45) NOT NULL,               -- 失败来源IP（组合维度的一部分）
    fail_count     INT         NOT NULL DEFAULT 0,      -- 该组合的连续失败次数
    locked_until   DATETIME,                            -- 该组合的锁定截止时间(空=未锁)
    last_failed_at DATETIME,                            -- 最近失败时间
    created_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT uk_login_user_ip UNIQUE (username, client_ip)
);
CREATE INDEX idx_login_username ON login_attempts (username);


-- =============================================================================
-- security_events —— 安全事件（§2.2.12 安全事件告警，增强项）
-- 由防线埋点自动生成：暴力破解锁定 / IP限流 / 越权403 / 非接收人取件 /
-- 密文篡改检出 / 超大分块 / 审计链断裂。actor_id 逻辑外键（同 audit_logs 约定，
-- 事件须能记录已删除用户与未登录来源）。
-- =============================================================================
CREATE TABLE security_events (
    id           BIGINT        NOT NULL AUTO_INCREMENT,
    event_type   VARCHAR(40)   NOT NULL,               -- BRUTE_FORCE_LOCK/IP_THROTTLED/ACCESS_DENIED/UNAUTHORIZED_FILE_ACCESS/CHUNK_TAMPER_DETECTED/OVERSIZED_CHUNK/AUDIT_CHAIN_BROKEN
    severity     VARCHAR(10)   NOT NULL,               -- HIGH / MEDIUM / LOW
    actor_id     BIGINT,                               -- 触发用户ID（可空：未登录暴力破解等）
    client_ip    VARCHAR(64),                          -- 来源IP
    resource     VARCHAR(255),                         -- 相关资源（URI/fileId/用户名）
    detail       VARCHAR(1000),                        -- 事件说明
    created_at   DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);
CREATE INDEX idx_secevt_type    ON security_events (event_type);
CREATE INDEX idx_secevt_created ON security_events (created_at);
