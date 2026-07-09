# ==================================================
#  LogSonar — Dockerfile (Production)
# ==================================================
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY app/ .

# Copy frontend
COPY static/ ./static/

# Create data directories
RUN mkdir -p /app/data/reports

# Expose port 80
EXPOSE 80

# Start server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]