#!/usr/bin/env bash
# Step5 文件服务 活体端到端冒烟（登录会话→init→上传→complete→收件箱→信封→下载→负例→管理员）
# 依赖：curl、openssl(支持 sm3)。不依赖 jq。
set -u
BASE=http://localhost:8080
T=$(mktemp -d)
PASS=0; FAIL=0
ok(){ echo "  ✅ $1"; PASS=$((PASS+1)); }
ng(){ echo "  ❌ $1"; FAIL=$((FAIL+1)); }

sm3b64(){ printf '%s' "$1" | openssl dgst -sm3 -binary | openssl base64 | tr -d '\r\n'; }
login(){ # $1=user $2=cookiejar
  curl -s -c "$2" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"Demo@123\"}" "$BASE/api/auth/login" >/dev/null; }

C0="CIPHERTEXT-CHUNK-0-DOWNLOAD"; C1="CIPHERTEXT-CHUNK-1-DOWNLOAD"
D0=$(sm3b64 "$C0"); D1=$(sm3b64 "$C1")
echo "openssl SM3(chunk0)=$D0"

echo "== 1. alice 登录 =="
login alice "$T/alice.cj"
me=$(curl -s -b "$T/alice.cj" "$BASE/api/auth/me")
echo "$me" | grep -q '"username":"alice"' && ok "alice 会话有效" || ng "alice 登录失败: $me"

echo "== 2. init-upload (alice→bob, 2 块) =="
INIT=$(cat <<JSON
{"encryptedMetadata":{"algorithm":"SM4","mode":"CBC_WITH_SM3","iv":"aXY=","ciphertext":"Y3Q=","digest":"ZA=="},
 "chunkSize":27,"chunkCount":2,"totalSize":54,
 "recipients":[{"recipientId":10002,"recipientIdentity":"user:corp001:10002:bob@example.com",
   "keyEnvelope":{"algorithm":"SM9","wrappedKey":"d2s=","keyDigest":"a2Q="}}]}
JSON
)
RESP=$(curl -s -b "$T/alice.cj" -H 'Content-Type: application/json' -d "$INIT" "$BASE/api/files/init-upload")
FID=$(echo "$RESP" | grep -oE '"fileId":"[^"]+"' | head -1 | sed 's/.*:"//;s/"$//')
[ -n "$FID" ] && ok "init 返回 fileId=$FID" || ng "init 失败: $RESP"

echo "== 3. 上传两块密文(带正确摘要) =="
S0=$(curl -s -o /dev/null -w '%{http_code}' -b "$T/alice.cj" -X PUT \
  -H 'Content-Type: application/octet-stream' -H "X-Chunk-Digest: $D0" -H 'X-Chunk-IV: aXY=' \
  --data-binary "$C0" "$BASE/api/files/$FID/chunks/0")
[ "$S0" = 200 ] && ok "chunk0 上传 200" || ng "chunk0 上传=$S0"
S1=$(curl -s -o /dev/null -w '%{http_code}' -b "$T/alice.cj" -X PUT \
  -H 'Content-Type: application/octet-stream' -H "X-Chunk-Digest: $D1" -H 'X-Chunk-IV: aXY=' \
  --data-binary "$C1" "$BASE/api/files/$FID/chunks/1")
[ "$S1" = 200 ] && ok "chunk1 上传 200" || ng "chunk1 上传=$S1"

echo "== 4. 负例：错摘要上传应 400 =="
SW=$(curl -s -o /dev/null -w '%{http_code}' -b "$T/alice.cj" -X PUT \
  -H 'Content-Type: application/octet-stream' -H 'X-Chunk-Digest: WRONG==' \
  --data-binary "$C0" "$BASE/api/files/$FID/chunks/0")
[ "$SW" = 400 ] && ok "错摘要被拒 400" || ng "错摘要应 400 实际=$SW"

echo "== 5. complete → AVAILABLE =="
CP=$(curl -s -b "$T/alice.cj" -X POST "$BASE/api/files/$FID/complete")
echo "$CP" | grep -q '"status":"AVAILABLE"' && ok "complete → AVAILABLE" || ng "complete: $CP"

echo "== 6. bob 登录 + 收件箱 =="
login bob "$T/bob.cj"
INBOX=$(curl -s -b "$T/bob.cj" "$BASE/api/files/inbox")
echo "$INBOX" | grep -q "$FID" && ok "bob 收件箱含该文件" || ng "收件箱缺失: $INBOX"

echo "== 7. bob 取密钥信封 =="
ENV=$(curl -s -b "$T/bob.cj" "$BASE/api/files/$FID/recipients/me/key-envelope")
echo "$ENV" | grep -q '"wrappedKey":"d2s="' && ok "信封含 wrappedKey" || ng "信封异常: $ENV"

echo "== 8. bob 下载 chunk0 + 校验摘要头/字节 =="
DH="$T/dl0.bin"
hdr=$(curl -s -b "$T/bob.cj" -D - -o "$DH" "$BASE/api/files/$FID/chunks/0/download")
xd=$(echo "$hdr" | grep -i '^X-Chunk-Digest:' | tr -d '\r' | sed 's/.*: //')
[ "$xd" = "$D0" ] && ok "X-Chunk-Digest 头== openssl SM3(独立交叉校验)" || ng "摘要头不符: 头=$xd 期望=$D0"
got=$(cat "$DH"); [ "$got" = "$C0" ] && ok "下载字节与原密文一致" || ng "字节不一致: $got"
rd=$(sm3b64 "$got"); [ "$rd" = "$xd" ] && ok "重算下载内容 SM3 == 头摘要(完整性)" || ng "重算不符"

echo "== 9. 负例：carol(非接收人)下载应 403 =="
login carol "$T/carol.cj"
SC=$(curl -s -o /dev/null -w '%{http_code}' -b "$T/carol.cj" "$BASE/api/files/$FID/chunks/0/download")
[ "$SC" = 403 ] && ok "非接收人下载被拒 403" || ng "非接收人应 403 实际=$SC"

echo "== 10. admin 看密文记录 =="
login admin "$T/admin.cj"
AF=$(curl -s -b "$T/admin.cj" "$BASE/api/admin/files")
echo "$AF" | grep -q "$FID" && ok "管理员密文记录含该文件" || ng "admin/files 缺失: $AF"
echo "$AF" | grep -q 'wrappedKey' && ng "管理员视图泄露 wrappedKey!" || ok "管理员视图不含 wrappedKey(不可解密)"
echo "== 负例：员工查 admin/files 应 403 =="
SE=$(curl -s -o /dev/null -w '%{http_code}' -b "$T/alice.cj" "$BASE/api/admin/files")
[ "$SE" = 403 ] && ok "员工查密文记录被拒 403" || ng "员工应 403 实际=$SE"

rm -rf "$T"
echo "================="
echo "PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" = 0 ] && echo "SMOKE: ALL GREEN" || echo "SMOKE: HAS FAILURES"
