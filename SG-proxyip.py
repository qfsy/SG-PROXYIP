import os
import json
import asyncio
import aiohttp
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
TTL = int(cfg["cloudflare"].get("ttl", 120))
PROXIED = cfg["cloudflare"].get("proxied", False)

RESOLVE_DOMAIN = cfg["resolve_domain"]
CHECK_URL_TEMPLATE = cfg["check_url_template"]

# ---------- 从 Secrets 获取敏感信息 ----------
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
    data = await fetch_json(session, url)
    if not data:
        return None

    # 若返回为对象而非数组
    if isinstance(data, dict):
        if data.get("success") is True and 0 < data.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
            return data.get("responseTime")
        else:
            return None

    # 若返回数组（兼容旧结构）
    if isinstance(data, list):
        for e in data:
            if e.get("success") is True and e.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
                return e.get("responseTime")
    return None

# ---------- 修改 DNS 解析部分 ----------
async def resolve_ips(domain):
    """使用 Cloudflare 公共 DNS-over-HTTPS 解析 A 记录"""
    url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, headers={'Accept':'application/dns-json'}, timeout=ClientTimeout(total=TIMEOUT)) as resp:
                j = await resp.json()
                if 'Answer' in j:
                    return list(set(a['data'] for a in j['Answer']))[:200]
        except:
            return []
    return []

# ---------- CF 操作 ----------
async def get_current_cf_ip():
    headers = {"Authorization": f"Bearer {CF_API_TOKEN}"}
    # 获取 zone id
    url = f"https://api.cloudflare.com/client/v4/zones?name={ZONE_NAME}"
    j = requests.get(url, headers=headers, timeout=TIMEOUT).json()
    if not j.get("result"):
        return None, None, None
    zone_id = j["result"][0]["id"]
    # 获取 record
    url2 = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={RECORD_NAME}"
    j2 = requests.get(url2, headers=headers, timeout=TIMEOUT).json()
    if not j2.get("result"):
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
    if not CF_API_TOKEN or not ZONE_NAME or not RECORD_NAME:
        await notify_tg("❌ CF 配置未设置完整（TOKEN/ZONE/RECORD）")
        return

    zone_id, record_id, current_ip = await get_current_cf_ip()

    async with aiohttp.ClientSession() as session:
        # 检测当前 CF IP
        if current_ip:
            rt = await check_ip(session, current_ip)
            if rt is not None and rt <= MAX_RESPONSE_TIME:
                await notify_tg(f"✅ 当前 IP {current_ip} 正常（{rt}ms），无需更新。")
                return

        # 解析候选 IP
        ips = await resolve_ips(RESOLVE_DOMAIN)
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
