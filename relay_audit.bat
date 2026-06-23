@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

:: 检查是否安装了 relay-audit
where relay-audit >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [i] relay-audit 未安装，尝试直接运行...
    if exist ".\venv\Scripts\relay-audit.exe" (
        .\venv\Scripts\relay-audit.exe %*
    ) else (
        python -m relay_audit %*
    )
) else (
    relay-audit %*
)

echo.
echo [i] 按任意键退出
pause >nul
exit /b %ERRORLEVEL%
