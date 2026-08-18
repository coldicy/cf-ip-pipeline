# ============================================================
# app.py · 后端代码（Flask Web API + 真实 IP 探测引擎 + GitHub 推送）
# ------------------------------------------------------------
# 功能：
#   1. Web 控制台托管（index.html 前端）+ REST API
#   2. IP 基础库：Cloudflare 官方 CIDR（自动拉取）+ 自定义第三方反代 CIDR
#   3. 多维评估：TCP 握手 / TLS 握手 / HTTP 状态码 / 多轮 P95 稳定性
#   4. 两级筛选：硬性过滤 → 软性加权排序 → Top N 优质 IP 榜
#   5. 结构化 YAML/JSON 输出（含元数据与地理/ASN 信息）
#   6. GitHub 安全推送（PAT 经环境变量注入，绝不写入镜像）
# 用法：
#   python app.py          # 启动 Web 控制台（0.0.0.0:8080）
#   python app.py --once   # 执行一次完整管道后退出（供 Supercronic 调度）
# ============================================================
#!/usr/bin/env python3
import os, re, sys, ssl, json, time, shutil, socket, random, threading, datetime, subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml
import requests
from flask import Flask, jsonify, request, send_from_directory

BASE = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("CONFIG_PATH", BASE / "config.yaml"))
CF_IPS_URL = "https://www.cloudflare.com/ips/"
VERSION = "1.0"

DEFAULTS = {
    "scan": {"timeout_seconds": 3, "rounds": 3, "concurrency": 50,
             "max_latency_ms": 300, "min_success_rate": 60, "max_candidates": 200},
    "sources": {"cloudflare_official": True, "custom_cidrs": []},
    "output": {"top_n": 20, "format": "yaml", "path": "output/best-cloudflare-ips.yaml"},
    "github": {"repo": "", "branch": "main", "file": "best-cloudflare-ips.yaml", "auto_push": True},
}

def deep_merge(base, over):
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base

def load_config():
    cfg = json.loads(json.dumps(DEFAULTS))
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            deep_merge(cfg, yaml.safe_load(f) or {})
    except Exception as e:
        print(f"[config] 配置文件加载失败，使用默认配置：{e}", flush=True)
    cfg["github"]["repo"] = os.environ.get("GITHUB_REPO", cfg["github"]["repo"])
    cfg["github"]["branch"] = os.environ.get("GITHUB_BRANCH", cfg["github"]["branch"])
    return cfg

CFG = load_config()

STATE = {
    "running": False, "phase": "idle", "progress": 0,
    "results": [], "stats": {"total": 0}, "logs": [],
    "last_run": None,
    "push": {"last": None, "ok": None, "count": 0, "commit": None},
    "started": time.time(),
}
LOCK = threading.Lock()

def now_iso():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg, level="INFO"):
    line = {"t": datetime.datetime.now().strftime("%H:%M:%S"), "msg": str(msg), "level": level}
    STATE["logs"].append(line)
    STATE["logs"] = STATE["logs"][-400:]
    print(f"[{line['t']}][{level}] {msg}", flush=True)

# ---------------- IP 基础库（双层结构） ----------------
def fetch_official_cidrs():
    """第一层：Cloudflare 官方权威 IP 段（每日自动更新来源）"""
    r = requests.get(CF_IPS_URL, timeout=15, headers={"User-Agent": f"cf-ip-pipeline/{VERSION}"})
    r.raise_for_status()
    return [l.strip() for l in r.text.splitlines() if "/" in l and not l.startswith("#")]

def cidr_sample(cidr, n):
    """IPv4 CIDR 均匀采样（避免全量扫描大段）"""
    try:
        net, bits = cidr.split("/")
        bits = int(bits)
        parts = [int(x) for x in net.split(".")]
        if len(parts) != 4 or not (0 <= bits <= 32):
            return []
        base = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        size = 1 << (32 - bits)
        base &= ~(size - 1)
        out, tries = set(), 0
        target = min(n, size)
        while len(out) < target and tries < target * 20:
            tries += 1
            v = base + random.randint(1, size - 1)
            out.add(".".join(str((v >> s) & 255) for s in (24, 16, 8, 0)))
        return list(out)
    except Exception:
        return []

# ---------------- 多维探测 ----------------
def probe_once(ip, timeout):
    """单轮探测：TCP 握手 → TLS 握手 → HTTP 请求，返回 (tcp_ms, tls_ms, code) 或 None"""
    raw = None
    try:
        t0 = time.perf_counter()
        raw = socket.create_connection((ip, 443), timeout=timeout)
        t1 = time.perf_counter()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(raw, server_hostname="www.cloudflare.com")
        raw = None
        t2 = time.perf_counter()
        s.sendall(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\n"
                  b"User-Agent: cf-ip-pipeline/1.0\r\nConnection: close\r\n\r\n")
        s.settimeout(timeout)
        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            chunk = s.recv(2048)
            if not chunk:
                break
            data += chunk
        s.close()
        m = re.search(rb"HTTP/1\.\d (\d{3})", data)
        return ((t1 - t0) * 1000, (t2 - t1) * 1000, int(m.group(1)) if m else None)
    except Exception:
        return None
    finally:
        if raw:
            try: raw.close()
            except Exception: pass

def percentile(vals, p):
    """百分位数（P95），避免平均值被异常慢响应扭曲"""
    if not vals:
        return None
    vals = sorted(vals)
    k = (len(vals) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(vals) - 1)
    return vals[f] + (vals[c] - vals[f]) * (k - f)

def probe_ip(ip):
    """多轮探测（稳定性评估）+ P95 聚合"""
    rounds = CFG["scan"]["rounds"]
    timeout = CFG["scan"]["timeout_seconds"]
    tcps, tlss, oks = [], [], 0
    for _ in range(rounds):
        r = probe_once(ip, timeout)
        if r and r[2] and 200 <= r[2] < 400:
            tcps.append(r[0]); tlss.append(r[0] + r[1]); oks += 1
    return {
        "ip_address": ip,
        "asn": "AS13335", "asn_name": "Cloudflare",
        "city": "", "country": "", "location": "",
        "tcp_handshake_latency_ms": round(percentile(tcps, 95), 1) if tcps else None,
        "tls_handshake_latency_ms": round(percentile(tlss, 95), 1) if tlss else None,
        "http_success_rate_percent": round(oks / rounds * 100),
        "rounds": rounds,
        "last_tested_timestamp": now_iso(),
    }

def enrich_geo(records):
    """附加信息：地理定位 + ASN（ip-api.com 批量接口）"""
    ips = [r["ip_address"] for r in records]
    idx = {r["ip_address"]: r for r in records}
    try:
        for i in range(0, len(ips), 100):
            resp = requests.post("http://ip-api.com/batch?fields=query,as,asname,country,city",
                                 json=ips[i:i + 100], timeout=10).json()
            for item in resp:
                rec = idx.get(item.get("query"))
                if not rec:
                    continue
                m = re.match(r"AS(\d+)", item.get("as") or "")
                if m:
                    rec["asn"] = "AS" + m.group(1)
                rec["asn_name"] = item.get("asname") or rec["asn_name"]
                rec["country"] = item.get("country") or ""
                rec["city"] = item.get("city") or ""
                rec["location"] = f"{rec['city']} {rec['country']}".strip()
    except Exception as e:
        log(f"地理位置富集失败（不影响主流程）：{e}", "WARN")

def score_of(r):
    """软性加权：延迟 55% + 成功率 45%"""
    maxl = max(CFG["scan"]["max_latency_ms"], 1)
    tcp = r["tcp_handshake_latency_ms"]
    if tcp is None:
        return 0
    lat_score = max(0.0, 1 - tcp / maxl)
    return round((lat_score * 0.55 + r["http_success_rate_percent"] / 100 * 0.45) * 100)

# ---------------- 输出与 GitHub 推送 ----------------
def write_output(records):
    doc = {
        "meta": {
            "version": VERSION,
            "generated_at": now_iso(),
            "generator": f"cf-ip-pipeline/{VERSION} (docker)",
            "criteria": {
                "max_tcp_latency_ms": CFG["scan"]["max_latency_ms"],
                "min_http_success_rate_percent": CFG["scan"]["min_success_rate"],
                "test_rounds": CFG["scan"]["rounds"],
                "percentile": "P95",
            },
            "total_candidates": STATE["stats"].get("total", 0),
            "passed_hard_filter": len(records),
        },
        "best_ips": records,
    }
    path = BASE / CFG["output"]["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if CFG["output"]["format"] == "json":
            json.dump(doc, f, ensure_ascii=False, indent=2)
        else:
            yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)
    return path

def push_github():
    """clone → 写入 YAML → add/commit/push；令牌仅经环境变量注入并在日志中脱敏"""
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = (CFG["github"].get("repo") or os.environ.get("GITHUB_REPO", "")).strip()
    branch = CFG["github"].get("branch") or "main"
    fname = CFG["github"].get("file") or "best-cloudflare-ips.yaml"
    if not STATE["results"]:
        log("无扫描结果，取消推送", "WARN"); return False
    if not repo:
        log("未配置 GitHub 仓库（config.yaml 或 GITHUB_REPO），跳过推送", "WARN"); return False
    if not token:
        log("GITHUB_TOKEN 未注入（docker run -e GITHUB_TOKEN=***），无法推送", "ERROR"); return False

    STATE["phase"] = "推送 GitHub"
    url = repo if repo.startswith("http") else f"https://github.com/{repo}"
    auth_url = url.replace("https://", f"https://x-access-token:{token}@")
    work = BASE / "work"
    shutil.rmtree(work, ignore_errors=True)

    def git(args, cwd=None):
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=180)
        out = (r.stdout + r.stderr).replace(token, "***")   # 日志脱敏
        if r.returncode != 0:
            raise RuntimeError(out.strip() or "git 命令执行失败")
        return out.strip()

    try:
        log(f"克隆仓库 {repo}（分支 {branch}，令牌经环境变量注入 ••••）", "PUSH")
        git(["clone", "--depth", "1", "-b", branch, auth_url, str(work)])
        shutil.copy(BASE / CFG["output"]["path"], work / fname)
        git(["add", fname], cwd=work)
        st = subprocess.run(["git", "status", "--porcelain"], cwd=work, capture_output=True, text=True).stdout
        if not st.strip():
            log("IP 列表无变化，无需提交", "INFO")
            STATE["push"].update(last=now_iso(), ok=True)
            return True
        git(["-c", "user.name=cf-ip-pipeline", "-c", "user.email=bot@cf-ip-pipeline",
             "commit", "-m", f"Update best Cloudflare IPs {now_iso()}"], cwd=work)
        git(["push", "origin", branch], cwd=work)
        h = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=work,
                           capture_output=True, text=True).stdout.strip()
        STATE["push"] = {"last": now_iso(), "ok": True, "commit": h, "count": STATE["push"]["count"] + 1}
        log(f"✔ 推送成功 · commit {h}", "OK")
        return True
    except Exception as e:
        STATE["push"]["last"] = now_iso(); STATE["push"]["ok"] = False
        log(f"推送失败：{e}", "ERROR")
        return False
    finally:
        shutil.rmtree(work, ignore_errors=True)

# ---------------- 六阶段管道 ----------------
def _scan_pipeline():
    # ① IP 基础库构建
    STATE.update(phase="获取 IP 基础库", progress=3)
    cidrs = []
    if CFG["sources"].get("cloudflare_official", True):
        try:
            cidrs += fetch_official_cidrs()
            log(f"已获取 Cloudflare 官方 CIDR：{len(cidrs)} 个", "OK")
        except Exception as e:
            log(f"官方 IP 列表获取失败：{e}", "ERROR")
    custom = CFG["sources"].get("custom_cidrs") or []
    if custom:
        cidrs += custom
        log(f"加载用户自定义第三方反代 CIDR：{len(custom)} 个")
    if not cidrs:
        log("IP 基础库为空，任务终止", "ERROR"); return

    max_total = CFG["scan"]["max_candidates"]
    per_cidr = max(1, max_total // len(cidrs))
    pool = []
    for c in cidrs:
        pool += cidr_sample(c, per_cidr)
    pool = pool[:max_total]
    STATE["stats"]["total"] = len(pool)
    log(f"候选池构建完成：{len(pool)} 个 IP（采样自 {len(cidrs)} 个 CIDR）", "OK")

    # ② 多维并发探测
    STATE.update(phase="TCP/TLS/HTTP 多轮探测")
    results, done = [], 0
    with ThreadPoolExecutor(max_workers=CFG["scan"]["concurrency"]) as ex:
        futs = {ex.submit(probe_ip, ip): ip for ip in pool}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                pass
            done += 1
            STATE["progress"] = 5 + int(done / len(pool) * 55)
            if done % max(1, len(pool) // 10) == 0:
                log(f"探测进度 {done}/{len(pool)}", "SCAN")

    # ③ 硬性过滤
    STATE.update(phase="硬性过滤", progress=65)
    max_lat = CFG["scan"]["max_latency_ms"]
    min_rate = CFG["scan"]["min_success_rate"]
    passed = [r for r in results
              if r["tcp_handshake_latency_ms"] is not None
              and r["tcp_handshake_latency_ms"] <= max_lat
              and r["http_success_rate_percent"] >= min_rate]
    log(f"硬性过滤：通过 {len(passed)} / {len(results)}（延迟≤{max_lat}ms 且成功率≥{min_rate}%）", "OK")

    # ④ 加权排序 + 地理富集
    STATE.update(phase="加权排序与地理富集", progress=72)
    for r in passed:
        r["quality_score"] = score_of(r)
    passed.sort(key=lambda r: r["quality_score"], reverse=True)
    enrich_geo(passed)
    best = passed[: CFG["output"]["top_n"]]

    # ⑤ 结构化输出
    STATE.update(phase="生成输出文件", progress=84)
    path = write_output(best)
    log(f"输出文件已生成：{path}（Top {len(best)}）", "OK")

    STATE["results"] = best
    STATE["last_run"] = now_iso()
    STATE["progress"] = 92

    # ⑥ GitHub 推送
    if CFG["github"].get("auto_push", True):
        push_github()
    else:
        log("auto_push=false，跳过自动推送")
    STATE["progress"] = 100
    STATE["phase"] = "完成"
    log("════ 管道任务完成 ════", "OK")

def run_scan():
    with LOCK:
        if STATE["running"]:
            return False
        STATE["running"] = True
    def job():
        try:
            _scan_pipeline()
        except Exception as e:
            log(f"管道执行异常：{e}", "ERROR")
        finally:
            STATE["running"] = False
            STATE["phase"] = "idle"
    threading.Thread(target=job, daemon=True).start()
    return True

# ---------------- Web 控制台 + REST API ----------------
app = Flask(__name__, static_folder=str(BASE), static_url_path="")

@app.route("/")
def index():
    return send_from_directory(str(BASE), "index.html")

@app.route("/api/health")
def api_health():
    return jsonify({"ok": True, "version": VERSION, "uptime": int(time.time() - STATE["started"])})

@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        flat = {
            "max_latency_ms": ("scan", "max_latency_ms"), "rounds": ("scan", "rounds"),
            "concurrency": ("scan", "concurrency"), "min_success_rate": ("scan", "min_success_rate"),
            "max_candidates": ("scan", "max_candidates"), "top_n": ("output", "top_n"),
            "output_format": ("output", "format"), "github_repo": ("github", "repo"),
            "github_branch": ("github", "branch"), "output_file": ("github", "file"),
            "auto_push": ("github", "auto_push"),
        }
        for k, v in data.items():
            if k in flat:
                a, b = flat[k]
                CFG[a][b] = v
            elif k == "custom_cidrs":
                CFG["sources"]["custom_cidrs"] = [x.strip() for x in str(v).splitlines() if x.strip()]
        log("配置已通过 Web 控制台更新")
        return jsonify({"ok": True})
    return jsonify(json.loads(json.dumps(CFG)))

@app.route("/api/scan", methods=["POST"])
def api_scan():
    return jsonify({"started": run_scan()})

@app.route("/api/status")
def api_status():
    return jsonify({
        "running": STATE["running"], "phase": STATE["phase"], "progress": STATE["progress"],
        "last_run": STATE["last_run"], "push": STATE["push"], "stats": STATE["stats"],
        "results": STATE["results"], "logs": STATE["logs"][-150:], "connected": True,
    })

@app.route("/api/results")
def api_results():
    return jsonify({"results": STATE["results"], "last_run": STATE["last_run"]})

@app.route("/api/push", methods=["POST"])
def api_push():
    ok = push_github()
    return jsonify({"ok": ok, "commit": STATE["push"].get("commit"),
                    "error": None if ok else "推送失败，详见日志"})

def main():
    if "--once" in sys.argv:
        log("════ 定时任务触发：执行完整管道 ════", "OK")
        _scan_pipeline()
        sys.exit(0)
    port = int(os.environ.get("PORT", "8080"))
    log(f"CF-IP Pipeline Web 控制台启动：http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, threaded=True)

if __name__ == "__main__":