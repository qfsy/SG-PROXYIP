import os
import json
import asyncio
import aiohttp
import socket
import requests
from aiohttp import ClientTimeout
from typing import Dict, List, Optional, Tuple

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
    """发送Telegram通知"""
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(
                url,
                json={"chat_id": TG_CHAT_ID, "text": message},
                timeout=ClientTimeout(total=5)
            )
    except Exception as e:
        print(f"[WARN] Telegram通知失败: {e}")

# ================= IP 检测 =================
async def check_target(session: aiohttp.ClientSession, target: str) -> Optional[float]:
    """检测目标（域名或IP）是否可用"""
    try:
        url = CHECK_URL_TEMPLATE.format(target)
        async with session.get(url, timeout=ClientTimeout(total=TIMEOUT)) as r:
            data = await r.json()
            
        # 解析响应时间
        response_time = None
        if isinstance(data, dict):
            success = str(data.get("success", "")).lower() in ("true", "1")
            if success:
                response_time = float(data.get("responseTime", 9999))
        elif isinstance(data, list) and data:
            for item in data:
                success = str(item.get("success", "")).lower() in ("true", "1")
                if success:
                    response_time = float(item.get("responseTime", 9999))
                    break
        
        if response_time and 0 < response_time <= MAX_RESPONSE_TIME:
            return response_time
        return None
        
    except Exception as e:
        print(f"[WARN] 检测失败 {target}: {e}")
        return None

# ================= DNS 解析 =================
def resolve_ips(domain: str) -> List[str]:
    """解析域名获取IP列表"""
    ips = set()
    
    # 使用socket解析
    try:
        result = socket.getaddrinfo(domain, 80, socket.AF_INET)
        for res in result:
            if res[0] == socket.AF_INET:
                ips.add(res[4][0])
    except Exception as e:
        print(f"[WARN] Socket解析失败 {domain}: {e}")
    
    # 使用DoH作为备选
    try:
        response = requests.get(
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
            headers={"Accept": "application/dns-json"},
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            for answer in data.get("Answer", []):
                if answer.get("type") == 1:
                    ips.add(answer["data"])
    except Exception as e:
        print(f"[WARN] DoH解析失败 {domain}: {e}")
    
    return list(ips)[:200]  # 限制数量

# ================= IP 国家检测 =================
async def check_ip_country(session: aiohttp.ClientSession, ip: str, target_country: str) -> bool:
    """检测IP所属国家"""
    try:
        async with session.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=ClientTimeout(total=5),
            headers={"User-Agent": "python-requests/2.25.1"}
        ) as r:
            if r.status == 200:
                data = await r.json()
                return data.get("country_code", "").upper() == target_country.upper()
    except aiohttp.ClientResponseError as e:
        if e.status == 429:
            print(f"[WARN] IPAPI.co请求受限，等待后重试 {ip}")
            await asyncio.sleep(2)  # 等待2秒后重试
            return await check_ip_country(session, ip, target_country)
    except Exception as e:
        print(f"[WARN] 国家检测失败 {ip}: {e}")
    
    # 备用API
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}",
            timeout=ClientTimeout(total=5),
            params={"fields": "countryCode"}
        ) as r:
            if r.status == 200:
                data = await r.json()
                return data.get("countryCode", "").upper() == target_country.upper()
    except Exception:
        pass
    
    return False

# ================= Cloudflare API =================
class CloudflareAPI:
    """Cloudflare API封装"""
    
    def __init__(self, token: str):
        self.token = token
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
    
    def get_zone_id(self, zone_name: str) -> Optional[str]:
        """获取Zone ID"""
        try:
            response = requests.get(
                f"{self.base_url}/zones",
                headers=self.headers,
                params={"name": zone_name},
                timeout=TIMEOUT
            )
            data = response.json()
            if data.get("success") and data.get("result"):
                return data["result"][0]["id"]
        except Exception as e:
            print(f"[ERROR] 获取Zone ID失败 {zone_name}: {e}")
        return None
    
    def get_dns_record(self, zone_id: str, record_name: str) -> Tuple[Optional[str], Optional[str]]:
        """获取DNS记录"""
        try:
            response = requests.get(
                f"{self.base_url}/zones/{zone_id}/dns_records",
                headers=self.headers,
                params={"name": record_name},
                timeout=TIMEOUT
            )
            data = response.json()
            if data.get("success") and data.get("result"):
                record = data["result"][0]
                return record["id"], record["content"]
        except Exception as e:
            print(f"[ERROR] 获取DNS记录失败 {record_name}: {e}")
        return None, None
    
    def update_dns_record(self, zone_id: str, record_id: str, record_name: str, ip: str) -> bool:
        """更新DNS记录"""
        try:
            response = requests.put(
                f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}",
                headers=self.headers,
                json={
                    "type": "A",
                    "name": record_name,
                    "content": ip,
                    "ttl": TTL,
                    "proxied": PROXIED
                },
                timeout=TIMEOUT
            )
            data = response.json()
            return data.get("success", False)
        except Exception as e:
            print(f"[ERROR] 更新DNS记录失败 {record_name}: {e}")
        return False

# ================= 单区域处理 =================
async def process_region(session: aiohttp.ClientSession, cf_api: CloudflareAPI, 
                         name: str, region: Dict) -> str:
    """处理单个区域"""
    
    # 获取Zone ID
    zone_id = cf_api.get_zone_id(region["zone_name"])
    if not zone_id:
        return f"{name.upper()} ❌ Zone不存在"
    
    # 获取当前记录
    record_id, current_ip = cf_api.get_dns_record(zone_id, region["record_name"])
    if not record_id:
        return f"{name.upper()} ❌ 记录不存在"
    
    # 1. 先检测当前域名是否可用
    current_response_time = await check_target(session, region["record_name"])
    if current_response_time:
        return f"{name.upper()} ⏭ 当前域名可用 ({current_response_time:.1f}ms)"
    
    # 2. 如果当前域名不可用，检测当前IP
    if current_ip:
        current_ip_response_time = await check_target(session, current_ip)
        if current_ip_response_time:
            # 检查当前IP的国家
            if await check_ip_country(session, current_ip, region["country"]):
                return f"{name.upper()} ⏭ 当前IP可用 ({current_ip_response_time:.1f}ms)"
    
    # 3. 解析域名获取IP列表
    ips = resolve_ips(region["resolve_domain"])
    if not ips:
        return f"{name.upper()} ❌ 无法解析IP"
    
    # 并行检测IP
    sem = asyncio.Semaphore(CONCURRENCY)
    valid_ips = {}
    
    async def test_ip(ip: str):
        """测试单个IP"""
        async with sem:
            try:
                # 先检测响应时间
                response_time = await check_target(session, ip)
                if not response_time:
                    return
                
                # 再检测国家
                if await check_ip_country(session, ip, region["country"]):
                    valid_ips[ip] = response_time
                    
            except Exception as e:
                print(f"[ERROR] {name} IP={ip} 检测异常: {e}")
    
    # 批量检测
    await asyncio.gather(*[test_ip(ip) for ip in ips])
    
    if not valid_ips:
        return f"{name.upper()} ❌ 无可用IP"
    
    # 选择最佳IP（响应时间最短）
    best_ip = min(valid_ips, key=lambda k: valid_ips[k])
    
    # 更新DNS记录
    if cf_api.update_dns_record(zone_id, record_id, region["record_name"], best_ip):
        return f"{name.upper()} ✅ {region['record_name']} → {best_ip} ({valid_ips[best_ip]:.1f}ms)"
    
    return f"{name.upper()} ❌ 更新失败"

# ================= 主入口 =================
async def main():
    """主函数"""
    cf_api = CloudflareAPI(CF_API_TOKEN)
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        for name, region in cfg["regions"].items():
            task = process_region(session, cf_api, name, region)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 处理结果
    formatted_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            region_name = list(cfg["regions"].keys())[i]
            formatted_results.append(f"{region_name.upper()} ❌ 处理异常: {result}")
        else:
            formatted_results.append(result)
    
    # 发送通知
    if formatted_results:
        message = "📊 DDNS 执行结果\n\n" + "\n".join(formatted_results)
        await notify_tg(message)
        
        # 同时在控制台输出（GitHub Actions会捕获）
        print(message)

if __name__ == "__main__":
    asyncio.run(main())
