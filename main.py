import os
import json
import asyncio
import aiohttp
import socket
import requests
from aiohttp import ClientTimeout

# ================= 读取配置 =================
REGIONS_JSON = os.environ.get("REGIONS_JSON")
if not REGIONS_JSON:
    raise RuntimeError("REGIONS_JSON 环境变量未设置")

cfg = json.loads(REGIONS_JSON)

MAX_RESPONSE_TIME = int(cfg.get("max_response_time", 800))
CONCURRENCY = int(cfg.get("concurrency", 4))
TIMEOUT = int(cfg.get("timeout_seconds", 6))
TTL = int(cfg["cloudflare"].get("ttl", 120))
PROXIED = cfg["cloudflare"].get("proxied", False)
CHECK_URL_TEMPLATE = cfg["check_url_template"]

# ================= Secrets =================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")

if not CF_API_TOKEN:
    raise RuntimeError("CF_API_TOKEN 环境变量未设置")

# ================= Telegram =================
async def notify_tg(message: str):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(
                url,
                json={"chat_id": TG_CHAT_ID, "text": message},
                timeout=5
            )
    except:
        pass

# ================= 检测域名响应 =================
async def fetch_json(session, url):
    try:
        async with session.get(url, timeout=ClientTimeout(total=TIMEOUT)) as r:
            return await r.json()
    except:
        return None

async def check_ip(session, target):
    """target 可以是 IP 或域名"""
    data = await fetch_json(session, CHECK_URL_TEMPLATE.format(target))
    if isinstance(data, dict):
        if data.get("success") and 0 < data.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
            return data["responseTime"]
    if isinstance(data, list):
        for e in data:
            if e.get("success") and 0 < e.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
                return e["responseTime"]
    return None

# ================= DNS 解析 =================
def resolve_ips(domain):
    ips = set()
    try:
        ips.update(socket.gethostbyname_ex(domain)[2])
    except:
        pass
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=TIMEOUT).json()
        for a in r.get("Answer", []):
            if a.get("type") == 1:
                ips.add(a["data"])
    except:
        pass
    return list(ips)[:200]

# ================= IP 国家判断 =================
async def is_country(session, ip, country_code):
    try:
        async with session.get(f"http://ipapi.co/{ip}/json/", timeout=ClientTimeout(total=5)) as r:
            if r.status == 200:
                return (await r.json()).get("country") == country_code
    except:
        pass
    return False

# ================= Cloudflare =================
def get_zone_id(zone_name):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones?name={zone_name}",
        headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
        timeout=TIMEOUT
    ).json()
    if not r.get("result"):
        return None
    return r["result"][0]["id"]

def get_record(zone_id, record_name):
    r = requests.get(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?name={record_name}",
        headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
        timeout=TIMEOUT
    ).json()
    if not r.get("result"):
        return None, None
    rec = r["result"][0]
    return rec["id"], rec["content"]

def update_record(zone_id, record_id, record_name, ip):
    r = requests.put(
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers={
            "Authorization": f"Bearer {CF_API_TOKEN}",
            "Content-Type": "application/json"
        },
        json={
            "type": "A",
            "name": record_name,
            "content": ip,
            "ttl": TTL,
            "proxied": PROXIED
        },
        timeout=TIMEOUT
    )
    return r.status_code == 200

# ================= 单区域处理 =================
async def process_region(session, name, region):
    # ---------------- 先检测当前解析是否有效 ----------------
    check_result = await check_ip(session, region["record_name"])
    if check_result is not None:
        # 检测成功且响应时间小于阈值，不更新
        return f"{name.upper()} ⏭ {region['record_name']} 当前解析有效 ({check_result}ms)，无需更新"

    # ---------------- 当前解析无效或超时，进行 DNS 更新 ----------------
    zone_id = get_zone_id(region["zone_name"])
    if not zone_id:
        return f"{name.upper()} ❌ Zone 不存在"

    ips = resolve_ips(region["resolve_domain"])
    if not ips:
        return f"{name.upper()} ❌ 无法解析"

    sem = asyncio.Semaphore(CONCURRENCY)
    valid = {}

    async def check(ip):
        async with sem:
            rt = await check_ip(session, ip)
            if rt and await is_country(session, ip, region["country"]):
                valid[ip] = rt

    await asyncio.gather(*[check(ip) for ip in ips])

    if not valid:
        return f"{name.upper()} ❌ 无可用 IP"

    best_ip = min(valid, key=valid.get)
    record_id, current_ip = get_record(zone_id, region["record_name"])

    if not record_id:
        return f"{name.upper()} ❌ 记录不存在"

    if current_ip == best_ip:
        return f"{name.upper()} ⏭ {region['record_name']} IP 未变化"

    if update_record(zone_id, record_id, region["record_name"], best_ip):
        return f"{name.upper()} ✅ {region['record_name']} → {best_ip} ({valid[best_ip]}ms)"

    return f"{name.upper()} ❌ 更新失败"

# ================= 主入口（只发一条 TG） =================
async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [
            process_region(session, name, region)
            for name, region in cfg["regions"].items()
        ]
        results = await asyncio.gather(*tasks)

    if results:
        message = "📊 DDNS 执行结果\n\n" + "\n".join(results)
        await notify_tg(message)

if __name__ == "__main__":
    asyncio.run(main())
