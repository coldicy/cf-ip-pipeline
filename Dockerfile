# Dockerfile · Alpine 轻量镜像 + Supercronic 容器化调度（PID 1）
FROM python:3.12-alpine

ARG TARGETARCH=amd64
ARG SUPERCRONIC_VERSION=v0.2.33

# git（推送）、curl（调试）、tzdata（时区）
RUN apk add --no-cache git curl tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Supercronic：专为容器设计的 cron（正确处理 SIGTERM，零沉默失败）
ADD https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH} /usr/local/bin/supercronic
RUN chmod +x /usr/local/bin/supercronic

# 后端 + 前端 + 配置 + 启动脚本
COPY app.py index.html config.yaml entrypoint.sh ./
RUN chmod +x /app/entrypoint.sh && mkdir -p /app/output

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CRON_SCHEDULE="*/30 * * * *"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]