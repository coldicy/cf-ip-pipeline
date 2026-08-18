#!/bin/sh
# ============================================================
# scan.sh · 定时任务脚本（新增文件，由 Supercronic 按 CRON_SCHEDULE 触发）
# 执行一次完整的六阶段管道：探测 → 过滤 → 排序 → YAML → 推送
# ------------------------------------------------------------
# 关键修复点：
#   · shebang + 显式 PATH（多阶段构建的 venv 路径 + 系统路径）
#   · 绝对路径解释器，杜绝任务上下文 PATH 缺失导致的 fork/exec 失败
# ============================================================
export PATH="/opt/venv/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

echo "[scan] $(date '+%Y-%m-%d %H:%M:%S') 定时任务触发：执行完整管道"
cd /app

if [ -x /opt/venv/bin/python ]; then
  exec /opt/venv/bin/python app.py --once
elif command -v python >/dev/null 2>&1; then
  exec python app.py --once
else
  echo "[scan] FATAL: 未找到 Python 解释器" >&2
  exit 1
fi