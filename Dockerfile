FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create uploads directory
RUN adduser --disabled-password appuser \
    && mkdir -p uploads \
    && chown appuser:appuser uploads \
    && chmod 755 uploads

USER appuser

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "main_fastapi:app", "--host", "0.0.0.0", "--port", "8000"] 