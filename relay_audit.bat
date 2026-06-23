@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

:: 优先使用安装的命令，否则回退到 python -m
where relay-audit >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    relay-audit %*
) else (
    python -m relay_audit %*
)

echo.
echo [i] 按任意键退出
pause >nul
exit /b %ERRORLEVEL%
