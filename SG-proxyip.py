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
TTL = int(cfg["cloudflare"].get("ttl", 120))
PROXIED = cfg["cloudflare"].get("proxied", False)

RESOLVE_DOMAIN = cfg["resolve_domain"]
CHECK_URL_TEMPLATE = os.environ.get("CHECK_URL_TEMPLATE", cfg.get("check_url_template"))

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

    # 若返回为对象
    if isinstance(data, dict):
        if data.get("success") is True and 0 < data.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
            return data.get("responseTime")
        else:
            return None

    # 若返回数组
    if isinstance(data, list):
        for e in data:
            if e.get("success") is True and 0 < e.get("responseTime", 9999) <= MAX_RESPONSE_TIME:
                return e.get("responseTime")
    return None

def resolve_ips_reliable(domain):
    """使用多种方法可靠地解析域名IP"""
    ips = []
    
    # 方法1: 使用socket.gethostbyname_ex
    try:
        _, _, socket_ips = socket.gethostbyname_ex(domain)
        ips.extend(socket_ips)
        print(f"Socket解析到IP: {socket_ips}")
    except Exception as e:
        print(f"Socket解析失败: {e}")
    
    # 方法2: 使用DNS-over-HTTPS (DoH)
    try:
        doh_url = f"https://dns.google/resolve?name={domain}&type=A"
        response = requests.get(doh_url, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            doh_ips = []
            for answer in data.get('Answer', []):
                if answer.get('type') == 1:  # A record
                    doh_ips.append(answer['data'])
            ips.extend(doh_ips)
            print(f"DoH解析到IP: {doh_ips}")
    except Exception as doh_e:
        print(f"DoH解析失败: {doh_e}")
    
    # 去重并限制数量
    ips = list(set(ips))[:200]
    print(f"最终解析到的IP列表: {ips}")
    return ips

async def check_ip_location(session, ip):
    """检查IP的地理位置"""
    try:
        # 使用ipapi.co检查IP地理位置
        url = f"http://ipapi.co/{ip}/json/"
        async with session.get(url, timeout=ClientTimeout(total=5)) as resp:
            if resp.status == 200:
                data = await resp.json()
                country = data.get('country', '')
                city = data.get('city', '')
                print(f"IP {ip} 地理位置: {country}, {city}")
                return country == 'SG'  # 新加坡的国家代码是SG
    except Exception as e:
        print(f"检查IP {ip} 地理位置失败: {e}")
    
    return False

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

        # 使用增强的DNS解析方法
        print(f"开始解析域名: {RESOLVE_DOMAIN}")
        all_ips = resolve_ips_reliable(RESOLVE_DOMAIN)
        
        if not all_ips:
            await notify_tg(f"❌ 无法从 {RESOLVE_DOMAIN} 解析到任何IP")
            return

        print(f"成功解析到 {len(all_ips)} 个IP，开始检测响应时间和地理位置...")

        # 并发检测候选 IP 的响应时间和地理位置
        semaphore = asyncio.Semaphore(CONCURRENCY)
        results = {}
        sg_ips = {}

        async def check(ip):
            async with semaphore:
                # 先检查响应时间
                rt = await check_ip(session, ip)
                if rt is not None:
                    results[ip] = rt
                    # 如果是响应时间合格的IP，再检查地理位置
                    is_sg = await check_ip_location(session, ip)
                    if is_sg:
                        sg_ips[ip] = rt

        await asyncio.gather(*[check(ip) for ip in all_ips])

        if not results:
            await notify_tg("❌ 没有可用的候选 IP")
            return

        # 优先选择新加坡的IP
        if sg_ips:
            best_ip = min(sg_ips, key=lambda k: sg_ips[k])
            best_time = sg_ips[best_ip]
            location_info = "新加坡"
            print(f"从 {len(sg_ips)} 个新加坡IP中选择最佳IP: {best_ip} (响应时间: {best_time}ms)")
        else:
            # 如果没有新加坡IP，选择所有IP中响应时间最短的
            best_ip = min(results, key=lambda k: results[k])
            best_time = results[best_ip]
            location_info = "非新加坡"
            print(f"警告: 没有找到新加坡IP，选择最佳IP: {best_ip} (响应时间: {best_time}ms)")
        
        success = update_cf_dns(zone_id, record_id, best_ip)
        if success:
            await notify_tg(f"⚡ DNS 更新成功：{RECORD_NAME} → {best_ip} ({best_time}ms) [{location_info}]")
        else:
            await notify_tg("❌ 更新 CF DNS 失败")

if __name__ == "__main__":

    asyncio.run(main())

