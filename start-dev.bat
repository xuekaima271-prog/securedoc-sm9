@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title SecureDoc 一键配环境并启动（dev 演示档）
cd /d "%~dp0"
set "ROOT=%~dp0"
set "TOOLS=%ROOT%.tools"
if not exist "%TOOLS%" mkdir "%TOOLS%"

echo ============================================================
echo  SecureDoc 企业级端到端加密文档投递系统 —— 一键启动（dev档）
echo  KGC :8081  /  后端 :8080  /  前端 :5173（均为本机地址）
echo ============================================================
echo.

rem ================= 1. Java 21 =================
set "JAVA_EXE="
java -version 2>&1 | findstr /C:"\"21" >nul
if not errorlevel 1 set "JAVA_EXE=java"
if not defined JAVA_EXE (
  if exist "%TOOLS%\jdk-21\bin\java.exe" (
    set "JAVA_HOME=%TOOLS%\jdk-21"
    set "JAVA_EXE=%TOOLS%\jdk-21\bin\java.exe"
  )
)
if not defined JAVA_EXE (
  echo [环境] 未找到 JDK 21，正在下载便携版 Temurin 21 到 .tools\ ...
  powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse' -OutFile '%TOOLS%\jdk.zip'"
  if errorlevel 1 goto :fail
  powershell -NoProfile -Command "Expand-Archive -Force '%TOOLS%\jdk.zip' '%TOOLS%\jdk-x'"
  for /d %%D in ("%TOOLS%\jdk-x\jdk-21*") do ren "%%D" "jdk-21"
  del "%TOOLS%\jdk.zip"
  rmdir "%TOOLS%\jdk-x"
  set "JAVA_HOME=%TOOLS%\jdk-21"
  set "JAVA_EXE=%TOOLS%\jdk-21\bin\java.exe"
)
if defined JAVA_HOME set "PATH=%JAVA_HOME%\bin;%PATH%"
echo [环境] Java 就绪：
"%JAVA_EXE%" -version 2>&1 | findstr /R "version"
echo.

rem ================= 2. Node.js =================
set "NODE_OK="
node -v >nul 2>&1
if not errorlevel 1 set "NODE_OK=1"
if not defined NODE_OK (
  if exist "%TOOLS%\node\node.exe" (
    set "PATH=%TOOLS%\node;%PATH%"
    set "NODE_OK=1"
  )
)
if not defined NODE_OK (
  echo [环境] 未找到 Node.js，正在下载便携版 Node 20 到 .tools\ ...
  powershell -NoProfile -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://nodejs.org/dist/v20.18.1/node-v20.18.1-win-x64.zip' -OutFile '%TOOLS%\node.zip'"
  if errorlevel 1 goto :fail
  powershell -NoProfile -Command "Expand-Archive -Force '%TOOLS%\node.zip' '%TOOLS%\node-x'"
  for /d %%D in ("%TOOLS%\node-x\node-v*") do ren "%%D" "node"
  del "%TOOLS%\node.zip"
  rmdir "%TOOLS%\node-x"
  set "PATH=%TOOLS%\node;%PATH%"
)
echo [环境] Node 就绪：
call node -v
echo.

rem ================= 3. KGC 主密钥口令（本机专用，存于已被 git 忽略的 data 目录） =================
set "PP_FILE=%ROOT%kgc-service\data\kgc-passphrase.txt"
if not exist "%ROOT%kgc-service\data" mkdir "%ROOT%kgc-service\data"
if not exist "%PP_FILE%" (
  for /f %%P in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')"') do set "PP=%%P"
  echo !PP!>"%PP_FILE%"
  echo [密钥] 已在本机生成 KGC 主密钥口令：kgc-service\data\kgc-passphrase.txt
  echo        这是本机演示钥的口令，切勿提交仓库、切勿外传；删掉整个 data 目录等于重置演示环境。
) else (
  set /p PP=<"%PP_FILE%"
  echo [密钥] 已读取本机 KGC 主密钥口令。
)
echo.

rem ================= 4. 构建（已有产物则跳过；加参数 rebuild 强制重建） =================
if /i "%~1"=="rebuild" del "%ROOT%backend-app\target\backend-app-0.0.1-SNAPSHOT.jar" "%ROOT%kgc-service\target\kgc-service-0.0.1-SNAPSHOT.jar" 2>nul
if not exist "%ROOT%kgc-service\target\kgc-service-0.0.1-SNAPSHOT.jar" (
  echo [构建] 打包 kgc-service（首次需联网下载依赖，请稍候）...
  pushd "%ROOT%kgc-service"
  call mvnw.cmd -q -DskipTests package
  set "RC=!ERRORLEVEL!"
  popd
  if not "!RC!"=="0" goto :fail
)
if not exist "%ROOT%backend-app\target\backend-app-0.0.1-SNAPSHOT.jar" (
  echo [构建] 打包 backend-app...
  pushd "%ROOT%backend-app"
  call mvnw.cmd -q -DskipTests package
  set "RC=!ERRORLEVEL!"
  popd
  if not "!RC!"=="0" goto :fail
)
if not exist "%ROOT%frontend\node_modules" (
  echo [构建] 安装前端依赖 npm install（首次较慢）...
  pushd "%ROOT%frontend"
  call npm install
  set "RC=!ERRORLEVEL!"
  popd
  if not "!RC!"=="0" goto :fail
)
echo [构建] 就绪。
echo.

rem ================= 5. 依次启动：KGC → 后端 → 前端 =================
echo [启动] KGC 服务 :8081 ...
start "SecureDoc-KGC" /D "%ROOT%kgc-service" cmd /k "set KGC_MASTER_PASSPHRASE=%PP%&& java -jar target\kgc-service-0.0.1-SNAPSHOT.jar"
call :waitport 8081 KGC
if errorlevel 1 goto :fail

echo [启动] 后端服务 :8080 ...
start "SecureDoc-Backend" /D "%ROOT%backend-app" cmd /k "java -jar target\backend-app-0.0.1-SNAPSHOT.jar"
call :waitport 8080 后端
if errorlevel 1 goto :fail

echo [启动] 前端 :5173 ...
start "SecureDoc-Frontend" /D "%ROOT%frontend" cmd /k "npm run dev"
call :waitport 5173 前端
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo  全部启动完成，正在打开浏览器：http://127.0.0.1:5173/login
echo  演示账号：alice / bob / carol / admin / auditor，口令均为 Demo@123
echo  停止服务：直接关掉那三个服务窗口即可。
echo ============================================================
start "" "http://127.0.0.1:5173/login"
pause
exit /b 0

:waitport
rem %1=端口 %2=名称；最多等 90 秒
for /l %%I in (1,1,45) do (
  curl -s -o NUL "http://127.0.0.1:%1/" && (echo   %2 已就绪。& exit /b 0)
  timeout /t 2 /nobreak >nul
)
echo   [超时] %2 未在 90 秒内就绪，请看它的服务窗口里的报错。
exit /b 1

:fail
echo.
echo [失败] 上一步出错，脚本已停下。请把上面的报错截图或复制发回排查。
pause
exit /b 1
