# ---------- 阶段 1：构建依赖 ----------
FROM python:3.12-alpine AS builder
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------- 阶段 2：干净运行镜像 ----------
FROM python:3.12-alpine

ARG TARGETARCH=amd64
ARG SUPERCRONIC_VERSION=v0.2.33

# git（GitHub 推送）、curl（调试）、tzdata（时区）
RUN apk add --no-cache git curl tzdata \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

WORKDIR /app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    CRON_SCHEDULE="*/30 * * * *"
COPY --from=builder /opt/venv /opt/venv

# Supercronic：容器原生 cron（PID 1 信号处理，零沉默失败）
# Apple Silicon / ARM 服务器构建时 TARGETARCH 由 buildx 自动注入为 arm64
ADD https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH} /usr/local/bin/supercronic
RUN chmod +x /usr/local/bin/supercronic

# 前端 + 后端 + 配置 + 入口脚本 + 定时任务脚本
COPY app.py index.html config.yaml entrypoint.sh scan.sh ./

# ★ 关键修复：统一 LF 换行（Windows CRLF 会导致 fork/exec 与解析错误）+ 执行权限
RUN chmod +x /app/entrypoint.sh /app/scan.sh \
    && sed -i 's/\r$//' /app/entrypoint.sh /app/scan.sh \
    && mkdir -p /app/output

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/api/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]