@echo off
REM HAK/GAL Firewall - One-Click System Launcher
REM Starts Ollama, Proxy Server, and Admin Dashboard

echo ========================================
echo   HAK/GAL Firewall System Launcher
echo ========================================
echo.

REM Check if .venv_hexa exists
set VENV_PATH=..\..\.venv_hexa
if not exist "%VENV_PATH%" (
    echo ERROR: .venv_hexa not found at %VENV_PATH%
    echo Please ensure you're running this from the correct directory.
    pause
    exit /b 1
)

echo [1/4] Starting Ollama server...
start "Ollama Server" cmd /k "ollama serve"
timeout /t 3 /nobreak >nul
echo    Ollama started in new window.

echo.
echo [2/4] Starting Proxy Server...
cd /d "%~dp0"
start "Proxy Server" cmd /k "%VENV_PATH%\Scripts\python.exe src\proxy_server.py"
timeout /t 5 /nobreak >nul
echo    Proxy server started in new window (port 8081).

echo.
echo [3/4] Waiting for proxy to be ready...
timeout /t 5 /nobreak >nul

echo.
echo [4/4] Starting Admin Dashboard...
start "Admin Dashboard" cmd /k "%VENV_PATH%\Scripts\python.exe -m streamlit run tools\admin_dashboard.py --server.port 8501"
timeout /t 3 /nobreak >nul
echo    Dashboard started in new window.

echo.
echo [5/5] Opening browser...
timeout /t 2 /nobreak >nul
start http://localhost:8501
echo    Browser opened.

echo.
echo ========================================
echo   SYSTEM ONLINE
echo ========================================
echo.
echo Services:
echo   - Ollama:        http://localhost:11434
echo   - Proxy Server:  http://localhost:8081
echo   - Admin Dashboard: http://localhost:8501
echo.
echo Press any key to exit this launcher...
echo (Services will continue running in their windows)
pause >nul

