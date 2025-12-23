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
    raise RuntimeError("REGIONS_JSON environment variable missing")

cfg = json.loads(REGIONS_JSON)

MAX_RESPONSE_TIME = int(cfg.get("max_response_time", 800))
CONCURRENCY = int(cfg.get("concurrency", 4))
TIMEOUT = int(cfg.get("timeout_seconds", 6))
CHECK_URL_TEMPLATE = cfg.get("check_url_template")
TTL = int(cfg.get("cloudflare", {}).get("ttl", 120))
PROXIED = bool(cfg.get("cloudflare", {}).get("proxied", False))

# ================= Secrets =================
CF_API_TOKEN = os.environ.get("CF_API_TOKEN")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID")

if not CF_API_TOKEN:
    raise RuntimeError("CF_API_TOKEN missing")

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
    except Exception as e:
        print(f"[WARN] Telegram notification failed: {e}")

# ================= IP 检测 =================
async def fetch_json(session, url):
    try:
        async with session.get(url, timeout=ClientTimeout(total=TIMEOUT)) as r:
            return await r.json()
    except Exception as e:
        print(f"[WARN] fetch_json failed for {url}: {e}")
        return None

async def check_ip(session, ip):
    data = await fetch_json(session, CHECK_URL_TEMPLATE.format(ip))
    if not data:
        return None
    # 支持 success 是 true/True/1/"true" 等情况
    def success_val(x):
        return str(x).lower() in ("true", "1")
    if isinstance(data, dict):
        if success_val(data.get("success")) and 0 < data.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
            return data["responseTime"]
    elif isinstance(data, list):
        for e in data:
            if success_val(e.get("success")) and 0 < e.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
                return e["responseTime"]
    return None

# ================= DNS 解析 =================
def resolve_ips(domain):
    ips = set()
    try:
        ips.update(socket.gethostbyname_ex(domain)[2])
    except Exception as e:
        print(f"[WARN] Socket解析失败 {domain}: {e}")
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=TIMEOUT).json()
        for a in r.get("Answer", []):
            if a.get("type") == 1:
                ips.add(a["data"])
    except Exception as e:
        print(f"[WARN] DoH解析失败 {domain}: {e}")
    return list(ips)[:200]

# ================= IP 国家检测 =================
async def is_country(session, ip, country_code):
    try:
        async with session.get(f"http://ipapi.co/{ip}/json/", timeout=ClientTimeout(total=5)) as r:
            if r.status == 200:
                return (await r.json()).get("country", "").upper() == country_code.upper()
    except Exception as e:
        print(f"[WARN] IP国家检测失败 {ip}: {e}")
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
    zone_id = get_zone_id(region["zone_name"])
    if not zone_id:
        return f"{name.upper()} ❌ Zone不存在"

    ips = resolve_ips(region["resolve_domain"])
    if not ips:
        return f"{name.upper()} ❌ 无法解析"

    sem = asyncio.Semaphore(CONCURRENCY)
    valid = {}

    async def check(ip):
        async with sem:
            try:
                rt = await check_ip(session, ip)
                country_ok = await is_country(session, ip, region["country"]) if rt else False
                print(f"[DEBUG] {name} IP={ip}, rt={rt}, country_ok={country_ok}")
                if rt and country_ok:
                    valid[ip] = rt
            except Exception as e:
                print(f"[ERROR] {name} IP={ip} 检测异常: {e}")

    await asyncio.gather(*[check(ip) for ip in ips])

    if not valid:
        return f"{name.upper()} ❌ 无可用IP"

    best_ip = min(valid, key=valid.get)
    record_id, current_ip = get_record(zone_id, region["record_name"])

    if not record_id:
        return f"{name.upper()} ❌ 记录不存在"

    if current_ip == best_ip:
        return f"{name.upper()} ⏭ 未变化"

    if update_record(zone_id, record_id, region["record_name"], best_ip):
        return f"{name.upper()} ✅ {region['record_name']} → {best_ip} ({valid[best_ip]}ms)"

    return f"{name.upper()} ❌ 更新失败"

# ================= 主入口 =================
async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [process_region(session, name, region) for name, region in cfg["regions"].items()]
        results = await asyncio.gather(*tasks)

    if results:
        message = "📊 DDNS 执行结果\n\n" + "\n".join(results)
        await notify_tg(message)

if __name__ == "__main__":
    asyncio.run(main())
