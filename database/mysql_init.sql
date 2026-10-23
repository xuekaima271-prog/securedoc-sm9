-- =============================================================================
-- MySQL 8 演示期一次性建库脚本（DB-6：必须 utf8mb4，否则中文乱码）
--
-- 用法（管理员执行，注意 --default-character-set=utf8mb4 保证脚本按 UTF-8 读取）：
--   mysql -uroot -p --default-character-set=utf8mb4 < database/mysql_init.sql
--   mysql -uroot -p --default-character-set=utf8mb4 securedoc     < database/schema.sql
--   mysql -uroot -p --default-character-set=utf8mb4 securedoc     < database/init_data.sql
--   mysql -uroot -p --default-character-set=utf8mb4 securedoc_kgc < database/schema.sql
--   mysql -uroot -p --default-character-set=utf8mb4 securedoc_kgc < database/init_data.sql
--
-- 说明：
--   · 应用服务器与 KGC 各用独立库（securedoc / securedoc_kgc），与 dev 双 H2 架构一致。
--     ⚠ 不要共库（两服务连同一库）——真 MySQL 联调实证（账本 Step11）：
--       1) createUser 事务内调 KGC，KGC 影子行插入撞后端未提交行锁 → 分布式死锁；
--       2) KGC 审计行无 SM3 哈希链字段，混入共享 audit_logs 会使 verifyChain 全链失败。
--     跨库身份一致性由 KGC register-identity 幂等登记保证。
--   · init_data.sql 末尾的 AUTO_INCREMENT=10006 语句在 MySQL 下建议执行（见其注释）。
--   · 演示最小授权（可选，替代 root）：
--       CREATE USER 'securedoc'@'localhost' IDENTIFIED BY '请改成强口令';
--       GRANT ALL PRIVILEGES ON securedoc.*     TO 'securedoc'@'localhost';
--       GRANT ALL PRIVILEGES ON securedoc_kgc.* TO 'securedoc'@'localhost';
--       FLUSH PRIVILEGES;
--   · 应用启动（prod 档）：
--       backend-app:  ./mvnw spring-boot:run -Dspring-boot.run.profiles=prod   (环境变量 DB_USER/DB_PASSWORD)
--       kgc-service:  ./mvnw spring-boot:run -Dspring-boot.run.profiles=prod
-- =============================================================================

CREATE DATABASE IF NOT EXISTS securedoc
    DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE DATABASE IF NOT EXISTS securedoc_kgc
    DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
