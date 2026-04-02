# Use a slim, official Python image
FROM python:3.10-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies (to help some Python packages compile)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to take advantage of Docker caching
COPY requirements.txt .

# Install dependencies (plus gunicorn and uvicorn for production)
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn uvicorn[standard]

# Copy the rest of the application code
COPY . .

# Expose the communication port
EXPOSE 8000

# Start the application using Gunicorn for production-grade serving
# We use the PORT environment variable if provided (common on Render/Railway)
CMD gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:${PORT:-8000}
