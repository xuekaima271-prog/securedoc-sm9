# =============================================================================
# 停止应用服务器(:8080)、KGC 服务(:8081) 与 前端(:5173)
# =============================================================================
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$any = $false
foreach ($p in 8080, 8081, 5173) {
    $conns = Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) {
        Write-Host "端口 $p 未在监听。" -ForegroundColor Yellow
        continue
    }
    $any = $true
    $conns.OwningProcess | Select-Object -Unique | ForEach-Object {
        try {
            Write-Host "停止端口 $p 的进程 PID $_ ..." -ForegroundColor Cyan
            Stop-Process -Id $_ -Force -ErrorAction Stop
        } catch {
            Write-Host "无法停止 PID $_：$($_.Exception.Message)" -ForegroundColor Red
        }
    }
}
if ($any) { Start-Sleep -Seconds 1; Write-Host "已停止。" -ForegroundColor Green }
else { Write-Host "没有需要停止的服务。" -ForegroundColor Yellow }
