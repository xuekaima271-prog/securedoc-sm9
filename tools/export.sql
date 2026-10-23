CALL CSVWRITE('./tools/out_users.csv', 'SELECT id, username, real_name FROM users ORDER BY id', 'charset=UTF-8');
CALL CSVWRITE('./tools/out_roles.csv', 'SELECT role_code, role_name, description FROM roles ORDER BY id', 'charset=UTF-8');
