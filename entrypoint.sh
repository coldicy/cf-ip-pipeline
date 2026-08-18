#!/bin/sh
# entrypoint.sh · Web 控制台（后台）+ Supercronic 调度器（PID 1）
set -e

SCHED="${CRON_SCHEDULE:-*/30 * * * *}"
CRON_FILE=/tmp/supercrontab

# 调度频率由环境变量动态生成 crontab
printf '%s cd /app && python app.py --once >> /proc/1/fd/1 2>&1\n' "$SCHED" > "$CRON_FILE"

echo "[entrypoint] 调度周期：$SCHED"
echo "[entrypoint] 启动后端 Web 控制台（端口 ${PORT:-8080}）..."

python /app/app.py &

echo "[entrypoint] 启动 Supercronic（优雅信号处理）..."
exec supercronic "$CRON_FILE"