import os
import json
import asyncio
import aiohttp
import socket
import requests
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from aiohttp import ClientTimeout, ClientResponseError
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# ================= 配置日志 =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ================= 配置类 =================
@dataclass
class CloudflareConfig:
    """Cloudflare配置"""
    ttl: int = 120
    proxied: bool = False

@dataclass
class RegionConfig:
    """区域配置"""
    zone_name: str
    record_name: str
    resolve_domain: str
    country: str

@dataclass
class AppConfig:
    """应用配置"""
    max_response_time: int
    concurrency: int
    timeout_seconds: int
    check_url_template: str
    cloudflare: CloudflareConfig
    regions: Dict[str, RegionConfig]

# ================= 安全工具 =================
class SecurityUtils:
    """安全工具类，用于脱敏处理"""
    
    @staticmethod
    def mask_ip(ip: str) -> str:
        """脱敏IP地址"""
        if not ip or '.' not in ip:
            return "***.***.***.***"
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.**.**"
        return "***.***.***.***"
    
    @staticmethod
    def mask_domain(domain: str) -> str:
        """脱敏域名"""
        if not domain:
            return "***"
        parts = domain.split('.')
        if len(parts) >= 2:
            # 保留主域名，脱敏子域名
            return f"***.{'.'.join(parts[-2:])}"
        return "***"
    
    @staticmethod
    def mask_url(url: str) -> str:
        """脱敏URL"""
        if not url:
            return "***"
        # 只显示协议和域名部分
        if '://' in url:
            protocol, rest = url.split('://', 1)
            domain = rest.split('/')[0]
            return f"{protocol}://{SecurityUtils.mask_domain(domain)}/***"
        return "***"

# ================= 配置加载器 =================
class ConfigLoader:
    """配置加载器"""
    
    @staticmethod
    def load() -> AppConfig:
        """从环境变量加载配置"""
        regions_json = os.environ.get("REGIONS_JSON")
        if not regions_json:
            raise RuntimeError("REGIONS_JSON environment variable missing")
        
        cfg = json.loads(regions_json)
        
        # 加载Cloudflare配置
        cf_cfg = cfg.get("cloudflare", {})
        cloudflare = CloudflareConfig(
            ttl=int(cf_cfg.get("ttl", 120)),
            proxied=bool(cf_cfg.get("proxied", False))
        )
        
        # 加载区域配置
        regions = {}
        for name, region_data in cfg.get("regions", {}).items():
            regions[name] = RegionConfig(
                zone_name=region_data["zone_name"],
                record_name=region_data["record_name"],
                resolve_domain=region_data["resolve_domain"],
                country=region_data["country"].upper()
            )
        
        return AppConfig(
            max_response_time=int(cfg.get("max_response_time", 800)),
            concurrency=int(cfg.get("concurrency", 4)),
            timeout_seconds=int(cfg.get("timeout_seconds", 6)),
            check_url_template=cfg.get("check_url_template"),
            cloudflare=cloudflare,
            regions=regions
        )

# ================= 检测器 =================
class HealthChecker:
    """健康检测器"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        
    @staticmethod
    def parse_success_value(value: Any) -> bool:
        """解析success字段值"""
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            return value.lower() in ("true", "1")
        elif isinstance(value, (int, float)):
            return value > 0
        return False
    
    @staticmethod
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    async def check_target(session: aiohttp.ClientSession, target: str, timeout: int) -> Optional[float]:
        """检测目标（域名或IP）是否可用"""
        try:
            # 脱敏目标用于日志
            masked_target = SecurityUtils.mask_domain(target) if '.' in target else SecurityUtils.mask_ip(target)
            
            async with session.get(
                target,
                timeout=ClientTimeout(total=timeout),
                ssl=False
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    response_time = None
                    if isinstance(data, dict):
                        if HealthChecker.parse_success_value(data.get("success")):
                            rt = data.get("responseTime")
                            if rt:
                                response_time = float(rt)
                                logger.debug(f"检测成功: {masked_target}, 响应时间: {response_time}ms")
                    elif isinstance(data, list) and data:
                        for item in data:
                            if HealthChecker.parse_success_value(item.get("success")):
                                rt = item.get("responseTime")
                                if rt:
                                    response_time = float(rt)
                                    logger.debug(f"检测成功: {masked_target}, 响应时间: {response_time}ms")
                                    break
                    
                    if response_time:
                        return response_time
                    
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
            logger.debug(f"检测失败: {masked_target}, 错误: {type(e).__name__}")
            return None
        
        logger.debug(f"检测未通过条件: {masked_target}")
        return None

# ================= DNS解析器 =================
class DNSResolver:
    """DNS解析器"""
    
    @staticmethod
    def resolve_ips(domain: str, timeout: int = 5) -> List[str]:
        """解析域名获取IP列表"""
        ips = set()
        masked_domain = SecurityUtils.mask_domain(domain)
        
        logger.info(f"开始解析域名: {masked_domain}")
        
        # 方法1: socket解析
        try:
            result = socket.getaddrinfo(
                domain, 
                80, 
                socket.AF_INET, 
                socket.SOCK_STREAM
            )
            for res in result:
                if res[0] == socket.AF_INET:
                    ips.add(res[4][0])
            if ips:
                logger.info(f"Socket解析成功: {masked_domain}, 找到 {len(ips)} 个IP")
                return list(ips)
        except (socket.gaierror, socket.timeout) as e:
            logger.debug(f"Socket解析失败: {masked_domain}, 错误: {type(e).__name__}")
        
        # 方法2: 使用多个公共DNS
        doh_services = [
            "https://cloudflare-dns.com/dns-query",
            "https://dns.google/resolve",
            "https://dns.alidns.com/resolve"
        ]
        
        for doh_url in doh_services:
            try:
                response = requests.get(
                    f"{doh_url}?name={domain}&type=A",
                    headers={"Accept": "application/dns-json"},
                    timeout=timeout
                )
                if response.status_code == 200:
                    data = response.json()
                    for answer in data.get("Answer", []):
                        if answer.get("type") == 1:
                            ips.add(answer["data"])
                    if ips:
                        logger.info(f"DoH解析成功: {masked_domain}, 找到 {len(ips)} 个IP")
                        break
            except requests.RequestException as e:
                logger.debug(f"DoH解析失败: {SecurityUtils.mask_url(doh_url)}, 错误: {type(e).__name__}")
                continue
        
        return list(ips)[:50]

# ================= 地理位置检测器 =================
class GeoLocator:
    """地理位置检测器"""
    
    @staticmethod
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=2),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def check_ip_country(
        self, 
        session: aiohttp.ClientSession, 
        ip: str, 
        target_country: str
    ) -> bool:
        """检测IP所属国家"""
        masked_ip = SecurityUtils.mask_ip(ip)
        
        # 使用多个地理位置服务提高可靠性
        services = [
            self._check_ipapi_co,
            self._check_ip_api_com
        ]
        
        for service in services:
            try:
                result = await service(session, ip, target_country)
                if result is not None:
                    logger.debug(f"地理位置检测: {masked_ip}, 目标国家: {target_country}, 结果: {result}")
                    return result
            except Exception as e:
                logger.debug(f"地理位置服务失败: {service.__name__}, IP: {masked_ip}, 错误: {type(e).__name__}")
                continue
        
        logger.debug(f"所有地理位置服务失败: {masked_ip}")
        return False
    
    async def _check_ipapi_co(self, session: aiohttp.ClientSession, ip: str, target_country: str) -> Optional[bool]:
        """使用ipapi.co检测"""
        try:
            async with session.get(
                f"https://ipapi.co/{ip}/json/",
                timeout=ClientTimeout(total=3),
                headers={"User-Agent": "python-requests/2.25.1"}
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("country_code", "").upper() == target_country.upper()
        except ClientResponseError as e:
            if e.status == 429:
                logger.debug(f"ipapi.co API限流，等待重试")
                await asyncio.sleep(1)
                raise
        return None
    
    async def _check_ip_api_com(self, session: aiohttp.ClientSession, ip: str, target_country: str) -> Optional[bool]:
        """使用ip-api.com检测"""
        try:
            async with session.get(
                f"http://ip-api.com/json/{ip}",
                timeout=ClientTimeout(total=3),
                params={"fields": "countryCode"}
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("countryCode", "").upper() == target_country.upper()
        except:
            pass
        return None

# ================= Cloudflare客户端 =================
class CloudflareClient:
    """Cloudflare API客户端"""
    
    def __init__(self, api_token: str, config: CloudflareConfig):
        self.api_token = api_token
        self.config = config
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self._zone_cache: Dict[str, str] = {}
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=3)
    )
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """发送HTTP请求"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        response = requests.request(
            method=method,
            url=url,
            headers=self.headers,
            timeout=self.config.timeout_seconds if hasattr(self.config, 'timeout_seconds') else 10,
            **kwargs
        )
        
        response.raise_for_status()
        data = response.json()
        
        if not data.get("success"):
            errors = data.get("errors", [])
            error_msg = "; ".join([str(e) for e in errors])
            raise Exception(f"Cloudflare API错误: {error_msg}")
        
        return data
    
    def get_zone_id(self, zone_name: str) -> Optional[str]:
        """获取Zone ID（带缓存）"""
        masked_zone = SecurityUtils.mask_domain(zone_name)
        
        if zone_name in self._zone_cache:
            logger.debug(f"从缓存获取Zone ID: {masked_zone}")
            return self._zone_cache[zone_name]
        
        try:
            logger.info(f"获取Zone ID: {masked_zone}")
            data = self._make_request("GET", f"/zones?name={zone_name}")
            if data.get("result"):
                zone_id = data["result"][0]["id"]
                self._zone_cache[zone_name] = zone_id
                logger.info(f"成功获取Zone ID: {masked_zone}")
                return zone_id
        except Exception as e:
            logger.error(f"获取Zone ID失败: {masked_zone}, 错误: {type(e).__name__}")
        
        return None
    
    def get_dns_record(self, zone_id: str, record_name: str) -> Tuple[Optional[str], Optional[str]]:
        """获取DNS记录"""
        masked_record = SecurityUtils.mask_domain(record_name)
        
        try:
            logger.info(f"获取DNS记录: {masked_record}")
            data = self._make_request(
                "GET", 
                f"/zones/{zone_id}/dns_records",
                params={"name": record_name}
            )
            
            if data.get("result"):
                record = data["result"][0]
                logger.info(f"成功获取DNS记录: {masked_record}")
                return record["id"], record["content"]
        except Exception as e:
            logger.error(f"获取DNS记录失败: {masked_record}, 错误: {type(e).__name__}")
        
        return None, None
    
    def update_dns_record(self, zone_id: str, record_id: str, record_name: str, ip: str) -> bool:
        """更新DNS记录"""
        masked_record = SecurityUtils.mask_domain(record_name)
        masked_ip = SecurityUtils.mask_ip(ip)
        
        try:
            logger.info(f"更新DNS记录: {masked_record} -> {masked_ip}")
            data = self._make_request(
                "PUT",
                f"/zones/{zone_id}/dns_records/{record_id}",
                json={
                    "type": "A",
                    "name": record_name,
                    "content": ip,
                    "ttl": self.config.ttl,
                    "proxied": self.config.proxied
                }
            )
            logger.info(f"成功更新DNS记录: {masked_record}")
            return True
        except Exception as e:
            logger.error(f"更新DNS记录失败: {masked_record}, 错误: {type(e).__name__}")
            return False

# ================= 区域处理器 =================
class RegionProcessor:
    """区域处理器"""
    
    def __init__(
        self,
        config: AppConfig,
        cloudflare_client: CloudflareClient,
        health_checker: HealthChecker,
        dns_resolver: DNSResolver,
        geo_locator: GeoLocator
    ):
        self.config = config
        self.cf_client = cloudflare_client
        self.health_checker = health_checker
        self.dns_resolver = dns_resolver
        self.geo_locator = geo_locator
    
    async def process_region(
        self, 
        session: aiohttp.ClientSession,
        name: str, 
        region: RegionConfig
    ) -> Dict[str, Any]:
        """处理单个区域"""
        logger.info(f"开始处理区域: {name.upper()}")
        
        # 1. 获取Zone ID
        zone_id = self.cf_client.get_zone_id(region.zone_name)
        if not zone_id:
            return {
                "name": name.upper(),
                "status": "failed",
                "message": "❌ Zone不存在",
                "success": False
            }
        
        # 2. 获取当前记录
        record_id, current_ip = self.cf_client.get_dns_record(zone_id, region.record_name)
        if not record_id:
            return {
                "name": name.upper(),
                "status": "failed",
                "message": "❌ DNS记录不存在",
                "success": False
            }
        
        # 3. 检查当前域名/IP是否可用
        current_status = await self._check_current_status(session, region, current_ip)
        if current_status:
            return current_status
        
        # 4. 查找可用IP
        best_ip_info = await self._find_best_ip(session, region, current_ip)
        if not best_ip_info:
            return {
                "name": name.upper(),
                "status": "failed",
                "message": "❌ 无可用IP",
                "old_ip": current_ip,
                "success": False
            }
        
        # 5. 更新DNS记录
        if self.cf_client.update_dns_record(zone_id, record_id, region.record_name, best_ip_info["ip"]):
            return {
                "name": name.upper(),
                "status": "success",
                "message": f"✅ {SecurityUtils.mask_domain(region.record_name)} → {SecurityUtils.mask_ip(best_ip_info['ip'])} ({best_ip_info['response_time']:.1f}ms)",
                "old_ip": current_ip,
                "new_ip": best_ip_info["ip"],
                "response_time": best_ip_info["response_time"],
                "success": True
            }
        
        return {
            "name": name.upper(),
            "status": "failed",
            "message": "❌ 更新失败",
            "old_ip": current_ip,
            "new_ip": best_ip_info["ip"],
            "success": False
        }
    
    async def _check_current_status(
        self, 
        session: aiohttp.ClientSession,
        region: RegionConfig,
        current_ip: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """检查当前状态"""
        # 检查当前域名
        url = self.config.check_url_template.format(region.record_name)
        rt = await self.health_checker.check_target(session, url, self.config.timeout_seconds)
        if rt:
            return {
                "name": region.record_name.split('.')[0].upper(),
                "status": "skipped",
                "message": f"⏭ 当前域名可用 ({rt:.1f}ms)",
                "success": True
            }
        
        # 检查当前IP
        if current_ip:
            url = self.config.check_url_template.format(current_ip)
            rt = await self.health_checker.check_target(session, url, self.config.timeout_seconds)
            if rt and rt <= self.config.max_response_time:
                # 验证IP国家
                if await self.geo_locator.check_ip_country(session, current_ip, region.country):
                    return {
                        "name": region.record_name.split('.')[0].upper(),
                        "status": "skipped",
                        "message": f"⏭ 当前IP可用 ({rt:.1f}ms)",
                        "old_ip": current_ip,
                        "success": True
                    }
        
        return None
    
    async def _find_best_ip(
        self,
        session: aiohttp.ClientSession,
        region: RegionConfig,
        current_ip: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        """查找最佳IP"""
        # 解析IP列表
        ips = self.dns_resolver.resolve_ips(region.resolve_domain, self.config.timeout_seconds)
        if not ips:
            logger.warning(f"区域 {region.record_name.split('.')[0].upper()}: 无法解析IP")
            return None
        
        logger.info(f"区域 {region.record_name.split('.')[0].upper()}: 找到 {len(ips)} 个候选IP")
        
        # 并行检测
        semaphore = asyncio.Semaphore(self.config.concurrency)
        valid_ips = []
        
        async def test_single_ip(ip: str):
            async with semaphore:
                try:
                    # 检测响应时间
                    url = self.config.check_url_template.format(ip)
                    rt = await self.health_checker.check_target(session, url, self.config.timeout_seconds)
                    if not rt or rt > self.config.max_response_time:
                        return
                    
                    # 检测国家
                    country_match = await self.geo_locator.check_ip_country(session, ip, region.country)
                    if country_match:
                        valid_ips.append({
                            "ip": ip,
                            "response_time": rt,
                            "country_match": True,
                            "is_current": (ip == current_ip)
                        })
                        
                except Exception as e:
                    logger.debug(f"IP检测失败: {SecurityUtils.mask_ip(ip)}, 错误: {type(e).__name__}")
        
        # 批量检测
        tasks = [test_single_ip(ip) for ip in ips]
        await asyncio.gather(*tasks)
        
        if not valid_ips:
            logger.warning(f"区域 {region.record_name.split('.')[0].upper()}: 没有找到符合条件的IP")
            return None
        
        logger.info(f"区域 {region.record_name.split('.')[0].upper()}: 找到 {len(valid_ips)} 个有效IP")
        
        # 按响应时间排序，选择最快的
        valid_ips.sort(key=lambda x: x["response_time"])
        return valid_ips[0]

# ================= 通知器 =================
class Notifier:
    """通知器"""
    
    def __init__(self, bot_token: Optional[str], chat_id: Optional[str]):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = bool(bot_token and chat_id)
    
    async def send_telegram(self, message: str) -> bool:
        """发送Telegram通知"""
        if not self.enabled:
            logger.info("Telegram通知已禁用")
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json={
                        "chat_id": self.chat_id,
                        "text": message,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True
                    },
                    timeout=ClientTimeout(total=5)
                ) as response:
                    success = response.status == 200
                    if success:
                        logger.info("Telegram通知发送成功")
                    else:
                        logger.warning(f"Telegram通知发送失败，状态码: {response.status}")
                    return success
        except Exception as e:
            logger.warning(f"Telegram通知失败: {type(e).__name__}")
            return False
    
    @staticmethod
    def format_results(results: List[Dict[str, Any]]) -> str:
        """格式化结果"""
        lines = ["📊 <b>DDNS 执行结果</b>\n"]
        
        for result in results:
            status_emoji = {
                "success": "✅",
                "skipped": "⏭",
                "failed": "❌"
            }.get(result.get("status", ""), "❓")
            
            lines.append(f"{status_emoji} <b>{result.get('name', '未知')}</b>: {result.get('message', '')}")
            
            old_ip = result.get("old_ip")
            new_ip = result.get("new_ip")
            if old_ip and new_ip:
                lines.append(f"   {SecurityUtils.mask_ip(old_ip)} → {SecurityUtils.mask_ip(new_ip)}")
            elif old_ip:
                lines.append(f"   当前IP: {SecurityUtils.mask_ip(old_ip)}")
        
        return "\n".join(lines)

# ================= 主应用 =================
class DDNSApplication:
    """DDNS应用主类"""
    
    def __init__(self):
        # 加载环境变量
        self.cf_token = os.environ.get("CF_API_TOKEN")
        self.tg_bot_token = os.environ.get("TG_BOT_TOKEN")
        self.tg_chat_id = os.environ.get("TG_CHAT_ID")
        
        if not self.cf_token:
            raise RuntimeError("CF_API_TOKEN environment variable missing")
        
        # 初始化组件
        self.config = ConfigLoader().load()
        self.cf_client = CloudflareClient(self.cf_token, self.config.cloudflare)
        self.health_checker = HealthChecker(self.config)
        self.dns_resolver = DNSResolver()
        self.geo_locator = GeoLocator()
        self.notifier = Notifier(self.tg_bot_token, self.tg_chat_id)
        
        self.processor = RegionProcessor(
            self.config,
            self.cf_client,
            self.health_checker,
            self.dns_resolver,
            self.geo_locator
        )
    
    async def run(self) -> List[Dict[str, Any]]:
        """运行应用"""
        logger.info("开始DDNS更新任务")
        logger.info(f"处理 {len(self.config.regions)} 个区域")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for name, region in self.config.regions.items():
                task = self.processor.process_region(session, name, region)
                tasks.append(task)
            
            # 执行所有任务
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 处理结果
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                region_name = list(self.config.regions.keys())[i]
                processed_results.append({
                    "name": region_name.upper(),
                    "status": "failed",
                    "message": f"❌ 处理异常: {type(result).__name__}",
                    "success": False
                })
                logger.error(f"区域 {region_name.upper()} 处理失败: {type(result).__name__}")
            else:
                processed_results.append(result)
        
        # 发送通知
        if processed_results:
            message = self.notifier.format_results(processed_results)
            await self.notifier.send_telegram(message)
            
            # 输出摘要日志
            success_count = sum(1 for r in processed_results if r.get("success") is True)
            skipped_count = sum(1 for r in processed_results if r.get("status") == "skipped")
            failed_count = sum(1 for r in processed_results if r.get("status") == "failed")
            
            logger.info(f"任务完成: {success_count}成功, {skipped_count}跳过, {failed_count}失败")
        
        return processed_results

# ================= 主入口 =================
def main():
    """主函数"""
    try:
        app = DDNSApplication()
        results = asyncio.run(app.run())
        
        # 检查是否有失败的更新
        failures = [r for r in results if r.get("status") == "failed"]
        if failures:
            logger.error(f"检测到 {len(failures)} 个失败任务")
            exit(1)
        else:
            logger.info("所有任务执行成功")
            exit(0)
            
    except Exception as e:
        logger.error(f"应用启动失败: {type(e).__name__}")
        exit(1)

if __name__ == "__main__":
    main()
