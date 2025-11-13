import os
import json
import asyncio
import aiohttp
from aiohttp import ClientTimeout
import requests

# ---------- 配置 ----------
CONFIG_FILE = "sg-proxyip.json"

with open(CONFIG_FILE, "r") as f:
    cfg = json.load(f)

# 非敏感配置从 JSON 获取
MAX_RESPONSE_TIME = int(os.environ.get("MAX_RESPONSE_TIME", cfg.get("max_response_time", 800)))
CONCURRENCY = int(cfg.get("concurrency", 4))
TIMEOUT = int(cfg.get("timeout_seconds", 6))
RETRIES = int(cfg.get("retries", 2))
TTL = int(cfg["cloudflare"].get("ttl", 120))
PROXIED = cfg["cloudflare"].get("proxied", False)

RESOLVE_DOMAIN = cfg["resolve_domain"]
CHECK_URL_TEMPLATE = cfg["check_url_template"]

# ---------- 敏感信息从 Secrets 获取 ----------
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
ZONE_NAME = os.environ.get("CF_ZONE_NAME")
RECORD_NAME = os.environ.get("CF_RECORD_NAME")

TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")

# ---------- Helper ----------
async def notify_tg(message):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TG_CHAT_ID, "text": message}
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, timeout=5):
                pass
        except:
            pass

async def fetch_json(session, url):
    try:
        async with session.get(url, timeout=ClientTimeout(total=TIMEOUT)) as resp:
            return await resp.json()
    except:
        return None

async def check_ip(session, ip):
    url = CHECK_URL_TEMPLATE.format(ip)
    for _ in range(RETRIES):
        try:
            data = await fetch_json(session, url)
            if isinstance(data, list):
                valid = [x for x in data if x.get("success") in [True, "true"] and "responseTime" in x]
                if valid:
                    min_rt = min(float(x["responseTime"]) for x in valid)
                    return min_rt
        except asyncio.TimeoutError:
            return None
        except:
            continue
    return None

async def resolve_ips():
    url = f"https://cloudflare-dns.com/dns-query?name={RESOLVE_DOMAIN}&type=A"
    headers = {"Accept": "application/dns-json"}
    async with aiohttp.ClientSession(headers=headers) as session:
        data = await fetch_json(session, url)
        if not data or "Answer" not in data:
            return []
        ips = list({a["data"] for a in data["Answer"]})
        return ips[:200]

async def get_current_cf_ip():
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    async with aiohttp.ClientSession(headers=headers) as session:
        # 获取 zone id
        url = f"https://api.cloudflare.com/client/v4/zones?name={ZONE_NAME}"
        j = await fetch_json(session, url)
        if not j or not j.get("result"):
            return None, None, None
        zone_id = j["result"][0]["id"]

        # 获取 record
        url2 = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={RECORD_NAME}"
        j2 = await fetch_json(session, url2)
        if not j2 or not j2.get("result"):
            return zone_id, None, None
        record = j2["result"][0]
        return zone_id, record["id"], record["content"]

def update_cf_dns(zone_id, record_id, ip):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}" if record_id else f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    method = requests.put if record_id else requests.post
    data = {"type": "A", "name": RECORD_NAME, "content": ip, "ttl": TTL, "proxied": PROXIED}
    try:
        resp = method(url, headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"}, json=data, timeout=TIMEOUT)
        return resp.status_code in [200, 201]
    except:
        return False

# ---------- 主流程 ----------
async def main():
    zone_id, record_id, current_ip = await get_current_cf_ip()

    async with aiohttp.ClientSession() as session:
        # 检测当前 IP
        if current_ip:
            rt = await check_ip(session, current_ip)
            if rt is not None and rt <= MAX_RESPONSE_TIME:
                await notify_tg(f"✅ 当前 IP {current_ip} 正常（{rt}ms），无需更新。")
                return

        # 获取候选 IP
        ips = await resolve_ips()
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
                # 超时或异常直接跳过

        await asyncio.gather(*[check(ip) for ip in ips])

        if not results:
            await notify_tg("❌ 没有可用的候选 IP")
            return

        best_ip = min(results, key=lambda k: results[k])
        success = update_cf_dns(zone_id, record_id, best_ip)
        if success:
            await notify_tg(f"⚡ DNS 更新成功：{RECORD_NAME} → {best_ip}")
        else:
            await notify_tg("❌ 更新 CF DNS 失败")

if __name__ == "__main__":
    asyncio.run(main())
