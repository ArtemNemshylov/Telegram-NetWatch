FROM python:3.12-slim

# libpcap is needed by scapy for packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py .

CMD ["python", "-u", "monitor.py"]
