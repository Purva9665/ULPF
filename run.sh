#!/usr/bin/env bash
echo "======================================================="
echo "  ULPF - Universal Log Pre-processing Framework"
echo "  Starting Local Control Room & Processing Engine..."
echo "======================================================="

# Start Backend
python -m uvicorn backend.main:app --port 8000 --reload &
BACKEND_PID=$!

# Start Frontend
cd frontend && npm run dev &
FRONTEND_PID=$!

echo "ULPF Prototype is running!"
echo "- Control Room UI: http://localhost:5173"
echo "- Backend REST & WS: http://localhost:8000"
echo "- Swagger API Docs: http://localhost:8000/docs"

trap "kill $BACKEND_PID $FRONTEND_PID" EXIT
wait
