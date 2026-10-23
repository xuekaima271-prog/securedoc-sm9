# =============================================================================
# 企业级端到端加密文档投递系统 —— 一键启动（开发模式）
# 无 Docker / 无需安装数据库：应用服务器用 H2 内存库，启动即自动建表+灌演示数据
# 用法：deploy\启动.bat 双击，或 PowerShell 执行本脚本
# 停止：本窗口按 Ctrl+C，或运行 deploy\stop-all.ps1
# =============================================================================
# 注意：不设 $ErrorActionPreference='Stop'，否则 java/mvnw 写 stderr 会被误判为错误而中断
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$Backend = Join-Path $PSScriptRoot "..\backend-app"
$Kgc = Join-Path $PSScriptRoot "..\kgc-service"
$Frontend = Join-Path $PSScriptRoot "..\frontend"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " 企业级端到端加密文档投递系统 — 一键启动 (dev / H2 / 免Docker)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1) 检查 Java（用 Get-Command 判断存在；java -version 输出到 stderr，单独放宽 ErrorAction 取版本）
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host "[X] 未找到 Java，请先安装 JDK 21+ 并配置 PATH" -ForegroundColor Red
    exit 1
}
$jv = (& { $ErrorActionPreference = 'Continue'; java -version 2>&1 | Select-Object -First 1 })
Write-Host "[1/3] Java 已就绪: $jv" -ForegroundColor Green

# 2) 检查端口 8080 / 8081 / 5173
foreach ($p in 8080, 8081, 5173) {
    $inUse = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if ($inUse) {
        Write-Host "[!] 端口 $p 已被占用 (PID $($inUse.OwningProcess))。" -ForegroundColor Yellow
        Write-Host "    如需重启，请先运行 deploy\stop-all.ps1" -ForegroundColor Yellow
        exit 1
    }
}
Write-Host "[2/3] 端口 8080 / 8081 / 5173 空闲" -ForegroundColor Green

# 3) 启动信息
Write-Host "[3/3] 启动 KGC(:8081)、应用服务器(:8080)、前端(:5173)（首次会下载依赖，请耐心等待 1-2 分钟）..." -ForegroundColor Green
Write-Host ""
Write-Host "  前端入口       : http://localhost:5173   <== 浏览器打开这里"
Write-Host "  应用服务器健康 : http://localhost:8080/api/health"
Write-Host "  KGC 健康       : http://localhost:8081/kgc/health"
Write-Host "  KGC 主公钥     : http://localhost:8081/kgc/sm9/master-public-key"
Write-Host "  H2 控制台      : http://localhost:8080/h2-console"
Write-Host "                   (JDBC URL: jdbc:h2:mem:securedoc , 用户名: sa , 密码留空)"
Write-Host "  演示账号       : alice / bob / carol / admin / auditor    密码统一: Demo@123"
Write-Host ""
Write-Host "  注：KGC/前端在独立窗口启动；前端经 Vite 代理 /api→:8080，KGC 令牌只在后端，不入浏览器"
Write-Host "  停止：本窗口 Ctrl+C 停应用服务器，再运行 deploy\stop-all.ps1 停 KGC/前端（或一并停三者）"
Write-Host "------------------------------------------------------------"

# 先在独立窗口启动 KGC（CWD 必须在 kgc-service：dev 档用 ../database 相对路径）
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location '$Kgc'; Write-Host 'KGC 服务 (:8081) 启动中...' -ForegroundColor Cyan; .\mvnw.cmd spring-boot:run '-Dspring-boot.run.profiles=dev'"
)

# 再在独立窗口启动前端（首次自动 npm install）
Start-Process powershell -ArgumentList @(
    '-NoExit', '-Command',
    "Set-Location '$Frontend'; Write-Host '前端 (:5173) 启动中...' -ForegroundColor Cyan; if (-not (Test-Path node_modules)) { npm install }; npm run dev"
)

# 再在本窗口前台启动应用服务器（CWD 必须在 backend-app：dev 档用 ../database 相对路径加载 schema/种子）
Set-Location $Backend
& .\mvnw.cmd spring-boot:run "-Dspring-boot.run.profiles=dev"
