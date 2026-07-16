# Stage 1: Build the React Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Build the FastAPI Backend
FROM python:3.11-slim
WORKDIR /app

# Install wget to download OPA
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download OPA binary
RUN wget -O /usr/local/bin/opa https://openpolicyagent.org/downloads/v0.58.0/opa_linux_amd64_static \
    && chmod +x /usr/local/bin/opa

# Copy backend code
COPY backend/ ./backend/
COPY opa/ ./opa/

# Copy the built frontend into a directory the backend can serve
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose the port Railway provides
EXPOSE $PORT

# Start the application using Uvicorn
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}
