import os
import json
import asyncio
import aiohttp
import socket
import requests
from aiohttp import ClientTimeout

CONFIG_FILE = "sg-proxyip.json"

# ---------- 读取 JSON 配置 ----------
with open(CONFIG_FILE, "r") as f:
    cfg = json.load(f)

MAX_RESPONSE_TIME = int(os.environ.get("MAX_RESPONSE_TIME", cfg.get("max_response_time", 800)))
CONCURRENCY = int(cfg.get("concurrency", 4))
TIMEOUT = int(cfg.get("timeout_seconds", 6))
RETRIES = int(cfg.get("retries", 2))
TTL = int(cfg.get("cloudflare", {}).get("ttl", 120))
PROXIED = bool(cfg.get("cloudflare", {}).get("proxied", False))

RESOLVE_DOMAIN = cfg["resolve_domain"]
CHECK_URL_TEMPLATE = cfg["check_url_template"]

# ---------- 从 Secrets 获取敏感信息 ----------
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
ZONE_NAME = os.environ.get("CF_ZONE_NAME")
RECORD_NAME = os.environ.get("CF_RECORD_NAME")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")

# ---------- Helper ----------
async def notify_tg(message: str):
    """Telegram 推送"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, timeout=5):
                pass
    except:
        pass


async def fetch_json(session, url):
    """通用 GET JSON"""
    try:
        async with session.get(url, timeout=ClientTimeout(total=TIMEOUT)) as resp:
            return await resp.json()
    except Exception:
        return None


async def check_ip(session, ip):
    """检测候选 IP"""
    url = CHECK_URL_TEMPLATE.format(ip)
    data = await fetch_json(session, url)
    if not data:
        return None

    if isinstance(data, dict):
        if data.get("success") and 0 < data.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
            return data.get("responseTime")
        return None

    if isinstance(data, list):
        for e in data:
            if e.get("success") and 0 < e.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
                return e.get("responseTime")
    return None


def resolve_ips_socket(domain):
    """使用系统 DNS 解析域名"""
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return list(set(ips))[:200]
    except:
        return []


async def get_current_cf_ip():
    """获取当前 Cloudflare 记录 IP"""
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    try:
        z = requests.get(f"https://api.cloudflare.com/client/v4/zones?name={ZONE_NAME}", headers=headers, timeout=TIMEOUT).json()
        if not z.get("result"):
            return None, None, None
        zone_id = z["result"][0]["id"]

        r = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={RECORD_NAME}", headers=headers, timeout=TIMEOUT).json()
        if not r.get("result"):
            return zone_id, None, None
        record = r["result"][0]
        return zone_id, record["id"], record["content"]
    except:
        return None, None, None


def update_cf_dns(zone_id, record_id, ip):
    """更新 Cloudflare DNS"""
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    data = {"type": "A", "name": RECORD_NAME, "content": ip, "ttl": TTL, "proxied": PROXIED}
    try:
        if record_id:
            resp = requests.put(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}", headers=headers, json=data, timeout=TIMEOUT)
        else:
            resp = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers, json=data, timeout=TIMEOUT)
        return resp.status_code in [200, 201]
    except:
        return False


# ---------- 主流程 ----------
async def main():
    if not CF_API_TOKEN or not ZONE_NAME or not RECORD_NAME:
        await notify_tg("❌ CF 配置未设置完整（TOKEN/ZONE/RECORD）")
        return

    zone_id, record_id, current_ip = await get_current_cf_ip()
    if not zone_id:
        await notify_tg("❌ 无法获取 Cloudflare Zone 信息")
        return

    async with aiohttp.ClientSession() as session:
        # 检测当前 CF IP 是否仍然可用
        if current_ip:
            rt = await check_ip(session, current_ip)
            if rt is not None:
                await notify_tg(f"✅ 当前 IP {current_ip} 正常（{rt}ms），无需更新。")
                return

        # 解析候选 IP
        ips = resolve_ips_socket(RESOLVE_DOMAIN)
        if not ips:
            await notify_tg("❌ 未解析到候选 IP")
            return

        # 并发检测候选 IP
        semaphore = asyncio.Semaphore(CONCURRENCY)
        results = {}

        async def check(ip):
            async with semaphore:
                rt = await check_ip(session, ip)
                if rt is not None:
                    results[ip] = rt

        await asyncio.gather(*[check(ip) for ip in ips])

        if not results:
            await notify_tg("❌ 没有可用的候选 IP（全部超时或无响应）")
            return

        best_ip = min(results, key=lambda k: results[k])
        success = update_cf_dns(zone_id, record_id, best_ip)
        if success:
            await notify_tg(f"⚡ DNS 更新成功：{RECORD_NAME} → {best_ip} （{results[best_ip]}ms）")
        else:
            await notify_tg("❌ 更新 CF DNS 失败")


if __name__ == "__main__":
    asyncio.run(main())
