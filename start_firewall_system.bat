@echo off
title HAK/GAL LAUNCHER
color 0A

echo ===================================================
echo    HAK/GAL SECURITY FIREWALL - SYSTEM STARTUP
echo ===================================================
echo.

:: 1. Activate Venv
if exist "..\..\.venv_hexa\Scripts\activate.bat" (
    echo [*] Activating Virtual Environment (.venv_hexa)...
    call ..\..\.venv_hexa\Scripts\activate.bat
) else (
    echo [!] WARNING: .venv_hexa not found. Trying global python...
)

:: 2. Start Ollama (New Window)
echo [*] Starting AI Core (Ollama)...
start "AI CORE - OLLAMA" cmd /k ollama serve

:: Wait for Ollama
timeout /t 5 /nobreak >nul

:: 3. Start Proxy (New Window)
echo [*] Starting Firewall Proxy...
cd /d "%~dp0"
if exist "..\..\.venv_hexa\Scripts\python.exe" (
    start "FIREWALL PROXY (Port 8081)" cmd /k "..\..\.venv_hexa\Scripts\python.exe src\proxy_server.py"
) else (
    start "FIREWALL PROXY (Port 8081)" cmd /k python src\proxy_server.py
)

:: Wait for Proxy
timeout /t 3 /nobreak >nul

:: 4. Start Dashboard (New Window)
echo [*] Starting Admin Cockpit...
if exist "..\..\.venv_hexa\Scripts\python.exe" (
    start "ADMIN DASHBOARD" cmd /k "..\..\.venv_hexa\Scripts\python.exe -m streamlit run tools\admin_dashboard.py"
) else (
    start "ADMIN DASHBOARD" cmd /k streamlit run tools\admin_dashboard.py
)

echo.
echo ===================================================
echo    SYSTEM ONLINE
echo    - Proxy: http://localhost:8081
echo    - Dashboard: http://localhost:8501
echo ===================================================
echo.
pause

