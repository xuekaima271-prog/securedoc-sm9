#!/usr/bin/env bash
# Step 2 数据库约束执行测试：不仅建表能跑，更要验证 CHECK/UNIQUE/FK/级联 真的会拦。
# 用 H2(MODE=MySQL) 实跑，负例=被拒绝才算 PASS，正例=被接受才算 PASS。
set -u
JAR=tools/h2.jar
DIR=tools/h2test
rm -rf "$DIR"; mkdir -p "$DIR"
URL="jdbc:h2:./$DIR/db;MODE=MySQL"
TMP=tools/_t.sql
pass=0; fail=0

run() { java -cp "$JAR" org.h2.tools.RunScript -url "$URL" -user sa -script "$1" 2>&1; }
runshow() { java -cp "$JAR" org.h2.tools.RunScript -url "$URL" -user sa -script "$1" -showResults 2>&1; }
errored() { echo "$1" | grep -qiE 'exception|violation|integrity|not found|already exists|constraint'; }

neg() { # 期望被拒绝
  printf '%s;\n' "$2" > "$TMP"; out=$(run "$TMP")
  if errored "$out"; then echo "  ✅ PASS  $1（被正确拒绝）"; pass=$((pass+1));
  else echo "  ❌ FAIL  $1（竟然插入成功！约束失效）"; fail=$((fail+1)); fi
}
pos() { # 期望成功
  printf '%s\n' "$2" > "$TMP"; out=$(run "$TMP")
  if errored "$out"; then echo "  ❌ FAIL  $1（被误拒）：$(echo "$out"|grep -iE 'exception|violation'|head -1)"; fail=$((fail+1));
  else echo "  ✅ PASS  $1（正确接受）"; pass=$((pass+1)); fi
}

echo "===== 加载 schema + init_data（UTF-8）====="
printf "RUNSCRIPT FROM './database/schema.sql' CHARSET 'UTF-8';\nRUNSCRIPT FROM './database/init_data.sql' CHARSET 'UTF-8';\n" > tools/_load.sql
lout=$(run tools/_load.sql); errored "$lout" && { echo "❌ 加载失败：$lout"; exit 1; } || echo "加载成功"

echo
echo "===== 正例：搭建一份文件+分块+接收人（应成功）====="
pos "插入文件 file-test-0001(sender=10001)" "INSERT INTO files (id,sender_id,encrypted_metadata,total_size,chunk_count,status) VALUES ('file-test-0001',10001,'{\"x\":1}',100,1,'AVAILABLE')"
pos "插入分块 (F1,idx0)" "INSERT INTO file_chunks (file_id,chunk_index,object_key,chunk_size,sm3_digest,upload_status) VALUES ('file-test-0001',0,'encrypted-files/file-test-0001/chunk-0.bin',100,'abc','UPLOADED')"
pos "插入接收人 (F1,bob=10002)" "INSERT INTO file_recipients (file_id,recipient_id,recipient_identity,key_envelope) VALUES ('file-test-0001',10002,'user:corp001:10002:bob@example.com','{\"algorithm\":\"SM9\"}')"

echo
echo "===== 负例：UNIQUE 唯一约束 ====="
neg "users.username 重复(alice)" "INSERT INTO users (username,password_hash) VALUES ('alice','x')"
neg "user_keys.user_id 重复(10001)" "INSERT INTO user_keys (user_id,sm9_identity,key_status) VALUES (10001,'brand-new-id','ISSUED')"
neg "user_keys.sm9_identity 重复(改bob指向alice身份)" "UPDATE user_keys SET sm9_identity='user:corp001:10001:alice@example.com' WHERE user_id=10002"
neg "file_chunks (file_id,chunk_index) 重复(F1,0)" "INSERT INTO file_chunks (file_id,chunk_index,object_key,sm3_digest,upload_status) VALUES ('file-test-0001',0,'k2','d2','UPLOADED')"
neg "file_recipients (file_id,recipient_id) 重复(F1,10002)" "INSERT INTO file_recipients (file_id,recipient_id,recipient_identity,key_envelope) VALUES ('file-test-0001',10002,'id','{}')"

echo
echo "===== 负例：CHECK 状态枚举 ====="
neg "users.status 非法值 FOO" "INSERT INTO users (username,password_hash,status) VALUES ('zz','x','FOO')"
neg "files.status 非法值 WRONG" "INSERT INTO files (id,sender_id,encrypted_metadata,status) VALUES ('file-bad',10001,'{}','WRONG')"
neg "file_chunks.upload_status 非法值 NOPE" "INSERT INTO file_chunks (file_id,chunk_index,object_key,sm3_digest,upload_status) VALUES ('file-test-0001',5,'k','d','NOPE')"

echo
echo "===== 负例：FK 外键 ====="
neg "file_chunks.file_id 指向不存在文件" "INSERT INTO file_chunks (file_id,chunk_index,object_key,sm3_digest) VALUES ('no-such-file',0,'k','d')"
neg "files.sender_id 指向不存在用户99999" "INSERT INTO files (id,sender_id,encrypted_metadata) VALUES ('file-x',99999,'{}')"

echo
echo "===== 负例：RESTRICT（删除被引用的接收人用户应被拒）====="
neg "删除用户 bob(10002)，其为 F1 接收人" "DELETE FROM users WHERE id=10002"

echo
echo "===== 正例+级联：删除文件应级联删除其分块与接收人 ====="
pos "删除文件 file-test-0001" "DELETE FROM files WHERE id='file-test-0001'"
printf "SELECT COUNT(*) AS chunks_left FROM file_chunks WHERE file_id='file-test-0001';\nSELECT COUNT(*) AS recipients_left FROM file_recipients WHERE file_id='file-test-0001';\n" > tools/_q.sql
echo "  级联后剩余（应均为0）:"; runshow tools/_q.sql | grep -E '\-\-> '

echo
echo "===== 探测：插入新用户(不给id)，H2 自增取到什么值 ====="
printf "INSERT INTO users (username,password_hash) VALUES ('newbie','x');\nSELECT id, username FROM users WHERE username='newbie';\n" > tools/_q2.sql
runshow tools/_q2.sql | grep -E '\-\-> '

echo
echo "############ 约束测试结果：$pass 通过 / $fail 失败 ############"
rm -f tools/_t.sql tools/_q.sql tools/_q2.sql tools/_load.sql
rm -rf "$DIR"
exit $fail