@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
cd /d "%~dp0"

set "EXIT_CODE=0"
set "RAN=0"

:: Method 1: Use installed relay-audit command
where relay-audit >nul 2>nul
if !ERRORLEVEL! EQU 0 (
    relay-audit %*
    set "EXIT_CODE=!ERRORLEVEL!"
    set "RAN=1"
)

:: Method 2: Fallback to py launcher
if !RAN! EQU 0 (
    where py >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        py -m relay_audit %*
        set "EXIT_CODE=!ERRORLEVEL!"
        set "RAN=1"
    )
)

:: Method 3: Fallback to python command
if !RAN! EQU 0 (
    where python >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        python -m relay_audit %*
        set "EXIT_CODE=!ERRORLEVEL!"
        set "RAN=1"
    )
)

:: Method 4: Try common Python install paths
if !RAN! EQU 0 (
    for %%P in (
        "%LOCALAPPDATA%\Programs\Python\Python314\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        "C:\Python314\python.exe"
        "C:\Python313\python.exe"
        "C:\Python312\python.exe"
    ) do (
        if !RAN! EQU 0 if exist "%%~P" (
            "%%~P" -m relay_audit %*
            set "EXIT_CODE=!ERRORLEVEL!"
            set "RAN=1"
        )
    )
)

:: All methods failed
if !RAN! EQU 0 (
    echo.
    echo [x] Cannot find relay-audit or Python. Please:
    echo     1. Run: pip install -e .
    echo     2. Make sure Python is in PATH
    echo     Or use: python -m relay_audit
    echo.
    set "EXIT_CODE=1"
)

:: Pause on interactive mode or error
if "%~1"=="" (
    echo.
    pause
) else if !EXIT_CODE! NEQ 0 (
    echo.
    echo [i] Error exit code: !EXIT_CODE!
    pause
)

exit /b !EXIT_CODE!
