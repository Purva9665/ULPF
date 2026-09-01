@echo off
echo =======================================================
echo   ULPF - Universal Log Pre-processing Framework
echo   Starting Local Control Room & Processing Engine...
echo =======================================================

echo Starting Backend API & WebSocket Engine on http://localhost:8000...
start cmd /k "python -m uvicorn backend.main:app --port 8000 --reload"

echo Starting Frontend Live Control Room on http://localhost:5173...
start cmd /k "cd frontend && npm run dev"

echo.
echo ULPF Prototype is starting up!
echo - Control Room UI: http://localhost:5173
echo - Backend REST & WS: http://localhost:8000
echo - Swagger API Docs: http://localhost:8000/docs
echo =======================================================
