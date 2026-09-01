@echo off
echo.
echo  ====================================
echo   Mobile Audit Tool - Web Server
echo  ====================================
echo.

cd /d "%~dp0"

echo [1/2] Checking dependencies...
python -c "import fastapi, uvicorn, aiosqlite, jinja2, python_multipart" 2>nul
if errorlevel 1 (
    echo [!] Installing dependencies...
    pip install -r requirements.txt
)

echo [2/2] Starting server...
echo.
echo  Open browser: http://localhost:8089
echo  Press Ctrl+C to stop
echo.

python app.py
