@echo off
setlocal
title Auditoria de seguridad
cd /d "%~dp0"

rem Comprueba si ya tenemos permisos de administrador
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Se necesitan permisos de administrador.
    echo Acepta la ventana de Windows que va a aparecer...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

rem -ExecutionPolicy Bypass solo afecta a esta ejecucion, no cambia nada del equipo
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0auditoria.ps1"

echo.
pause
