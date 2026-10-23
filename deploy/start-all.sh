#!/usr/bin/env bash
# =============================================================================
# 一键启动（Git Bash 版）。等价于 start-all.ps1：KGC(:8081) + 应用(:8080) + 前端(:5173)
# 用法：bash deploy/start-all.sh    停止：Ctrl+C（会连带停后台 KGC/前端）
# =============================================================================
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$SCRIPT_DIR/../backend-app"
KGC="$SCRIPT_DIR/../kgc-service"
FRONTEND="$SCRIPT_DIR/../frontend"

echo "============================================================"
echo " 企业级端到端加密文档投递系统 — 一键启动 (dev / H2 / 免Docker)"
echo "============================================================"

command -v java >/dev/null 2>&1 || { echo "[X] 未找到 Java，请安装 JDK 21+"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "[X] 未找到 Node.js，请安装 Node 18+"; exit 1; }
echo "[1/3] Java: $(java -version 2>&1 | head -1)"

for p in 8080 8081 5173; do
  if netstat -ano 2>/dev/null | grep -E "[:.]${p}[^0-9]" | grep -qi LISTEN; then
    echo "[!] 端口 $p 已被占用，请先运行 deploy/stop-all.ps1 或停止占用进程"; exit 1
  fi
done
echo "[2/3] 端口 8080/8081/5173 空闲"

echo "[3/3] 启动三服务（首次下载依赖较慢）..."
echo
echo "  前端入口 : http://localhost:5173   <== 浏览器打开这里"
echo "  应用健康 : http://localhost:8080/api/health"
echo "  KGC 健康 : http://localhost:8081/kgc/health"
echo "  演示账号 : alice/bob/carol/admin/auditor  密码 Demo@123"
echo "  停止：Ctrl+C"
echo "------------------------------------------------------------"

# 后台：KGC（CWD 必须在 kgc-service：dev 档用 ../database 相对路径）
( cd "$KGC" && exec ./mvnw -q spring-boot:run -Dspring-boot.run.profiles=dev ) &
KGC_PID=$!

# 后台：前端（首次自动 npm install）
( cd "$FRONTEND" && { [ -d node_modules ] || npm install; } && exec npm run dev ) &
FE_PID=$!

cleanup() { kill "$KGC_PID" "$FE_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# 前台：应用服务器
cd "$BACKEND"
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
