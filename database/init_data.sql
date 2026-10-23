-- =============================================================================
-- 初始化演示数据 init_data.sql
-- 对应设计文档 §10(部署) 演示账号 / §18.11 第二步(插入 Alice/Bob/Admin 等)
--
-- 演示账号统一密码：Demo@123
--   password_hash 为 BCrypt($2b$,10) 真实哈希，Spring Security BCryptPasswordEncoder 可直接校验
--   （由 poc-crypto 用 bcryptjs 生成并验证 compareSync=true）
--
-- 用户ID 采用 10001 起，便于与 SM9 身份标识 user:corp001:{userId}:{email} 对应
-- 执行顺序：先 roles，再 users，再 user_roles / user_keys
-- =============================================================================

-- ---- 角色（6 个角色编码；种子分配 EMPLOYEE/SYS_ADMIN/SUPER_ADMIN/SECURITY_AUDITOR，DEPT_ADMIN 不分配）----
INSERT INTO roles (role_code, role_name, description) VALUES
    ('EMPLOYEE',         '普通员工',   '发送/接收文件、解密下载、SM9 密钥初始化'),
    ('SYS_ADMIN',        '系统管理员', '管理普通用户、查看密文文件记录(不可解密)、查看基础审计'),
    ('SUPER_ADMIN',      '超级管理员', '最高权限：任免管理员账号（仅种子初始管理员持有，后续只能由超管授予）'),
    ('SECURITY_AUDITOR', '安全审计员', '查看审计日志与安全事件'),
    ('DEPT_ADMIN',       '部门管理员', '后续扩展，MVP 不分配'),
    ('KGC_ADMIN',        'KGC管理员',  '查看 KGC 私钥签发记录');

-- ---- 用户（密码均为 Demo@123）----
INSERT INTO users (id, username, password_hash, real_name, email, status) VALUES
    (10001, 'alice',   '$2b$10$wW52aoswHz7zqmCpAbltfOV/.d2orz/Hf.cp/l4UCGs/9Xia6y.Ny', '爱丽丝', 'alice@example.com',   'ACTIVE'),
    (10002, 'bob',     '$2b$10$fKaYXquTdrSuINDE38hgPO.HFmA8NdPbL8onPuMcYYcLLUCd.xAXe', '鲍勃',   'bob@example.com',     'ACTIVE'),
    (10003, 'carol',   '$2b$10$vstFM4Gk4asN.iO/VWv0.eUBwyoQfadg0Cex.60zjmRinKwDe2D9S', '卡萝尔', 'carol@example.com',   'ACTIVE'),
    (10004, 'admin',   '$2b$10$ukEzsfY8aSg74lWf21VpBeyAJMGpaSgoCicvtrCfPLXzwpNIB9GjS', '系统管理员', 'admin@example.com', 'ACTIVE'),
    (10005, 'auditor', '$2b$10$nTzpaRgN8DhiJCPLQEWK.eAfqVejBWCtonAbcZpSNhET7viWbbOpK', '安全审计员', 'auditor@example.com','ACTIVE');

-- ---- 用户角色分配（用子查询按 role_code 取 id，避免硬编码角色ID）----
INSERT INTO user_roles (user_id, role_id) SELECT 10001, id FROM roles WHERE role_code = 'EMPLOYEE';
INSERT INTO user_roles (user_id, role_id) SELECT 10002, id FROM roles WHERE role_code = 'EMPLOYEE';
INSERT INTO user_roles (user_id, role_id) SELECT 10003, id FROM roles WHERE role_code = 'EMPLOYEE';
INSERT INTO user_roles (user_id, role_id) SELECT 10004, id FROM roles WHERE role_code = 'SYS_ADMIN';
INSERT INTO user_roles (user_id, role_id) SELECT 10004, id FROM roles WHERE role_code = 'SUPER_ADMIN';
INSERT INTO user_roles (user_id, role_id) SELECT 10005, id FROM roles WHERE role_code = 'SECURITY_AUDITOR';

-- ---- SM9 身份标识（key_status=UNINITIALIZED：尚未向 KGC 签发私钥）----
-- 身份格式：user:{tenantId}:{userId}:{email}，tenantId 固定 corp001
INSERT INTO user_keys (user_id, sm9_identity, key_status) VALUES
    (10001, 'user:corp001:10001:alice@example.com',   'UNINITIALIZED'),
    (10002, 'user:corp001:10002:bob@example.com',     'UNINITIALIZED'),
    (10003, 'user:corp001:10003:carol@example.com',   'UNINITIALIZED'),
    (10004, 'user:corp001:10004:admin@example.com',   'UNINITIALIZED'),
    (10005, 'user:corp001:10005:auditor@example.com', 'UNINITIALIZED');

-- MySQL 演示期推进自增起点（H2 无需执行，可忽略报错）：
-- ALTER TABLE users AUTO_INCREMENT = 10006;
