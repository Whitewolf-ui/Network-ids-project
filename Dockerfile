FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Copy and make entrypoint executable
COPY docker-entrypoint.sh /
RUN chmod +x /docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]