FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL https://github.com/aptible/supercronic/releases/download/v0.2.33/supercronic-linux-amd64 \
       -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scripts/ /app/scripts/
COPY config/ /app/config/
COPY cron/crontab /app/crontab
RUN mkdir -p /app/logs /app/data
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["supercronic", "/app/crontab"]
