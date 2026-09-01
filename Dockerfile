# Multi-stage Dockerfile for ULPF (Universal Log Pre-processing Framework)
# Stage 1: Build Frontend Assets
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Backend with Static Serving
FROM python:3.11-slim
WORKDIR /app

# Install system utilities (curl for container healthcheck) and python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend Code
COPY backend/ ./backend/

# Copy Built Frontend to Static Directory
COPY --from=frontend-builder /app/frontend/dist /app/static

# Create persistent storage directory for SQLite WAL volume
RUN mkdir -p /data

# Expose HTTP and WebSocket port
EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    ULPF_STATIC_DIR=/app/static \
    ULPF_DB_PATH=/data/ulpf_events.db \
    ULPF_LOG_LEVEL=INFO

# Health check using local API endpoint
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
