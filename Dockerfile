FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=5000

WORKDIR /app

# Install system dependencies required by Scapy for PCAP parsing
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure runtime storage directories exist
RUN mkdir -p /app/evidence /app/pcaps/uploads /app/reports

EXPOSE 5000

# Run via production Waitress WSGI entrypoint
CMD ["python", "wsgi.py"]

