-- 校验：表数量、各表行数、关键约束、连表查询
SELECT '== tables ==' AS info;
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='PUBLIC' ORDER BY TABLE_NAME;

SELECT '== row counts ==' AS info;
SELECT 'roles' AS t, COUNT(*) AS n FROM roles
UNION ALL SELECT 'users', COUNT(*) FROM users
UNION ALL SELECT 'user_roles', COUNT(*) FROM user_roles
UNION ALL SELECT 'user_keys', COUNT(*) FROM user_keys;

SELECT '== users joined with roles & sm9 identity ==' AS info;
SELECT u.id, u.username, r.role_code, u.status, k.sm9_identity, k.key_status
FROM users u
JOIN user_roles ur ON ur.user_id = u.id
JOIN roles r       ON r.id = ur.role_id
JOIN user_keys k   ON k.user_id = u.id
ORDER BY u.id;
