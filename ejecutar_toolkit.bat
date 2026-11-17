@echo off
chcp 65001 >nul
cd /d "%~dp0"

REM Si ya se esta ejecutando como administrador, ir directo al toolkit
net session >nul 2>&1
if %errorlevel%==0 goto ejecutar

echo.
echo ============================================
echo            IT TOOLKIT - Modo de ejecucion
echo ============================================
echo.
echo   [A] Ejecutar como ADMINISTRADOR (todas las opciones)
echo   [N] Ejecutar como usuario NORMAL
echo.
choice /c AN /n /m "Elige A o N: "
if errorlevel 2 goto ejecutar

REM --- Reabrir este mismo .bat con permisos de administrador (UAC) ---
if "%~1"=="" (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
) else (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%*' -Verb RunAs"
)
exit /b

:ejecutar
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0it_toolkit.ps1" %*
if not "%~1"=="" pause
