import requests
import time
import random
import re
import json
from urllib.parse import urlparse, urljoin
import argparse
import sys
from typing import Dict, List, Tuple, Optional

# ASCII Logo
LOGO = """
                     _     _     __          __
     ____ ___  _____| |   | |    \ \        / /
    / __ `__ \/ ___/ |   | |     \ \  /\  / / 
   / / / / / / /   | |___| |___   \ \/  \/ /  
  /_/ /_/ /_/_/    |_____|_____|   \  /\  /   
                                    \/  \/    
                         Web Application Firewall Detector
"""

# 扩展的WAF特征库
WAF_SIGNATURES = {
    "headers": {
        "Cloudflare": ["cf-ray", "cf-request-id", "server: cloudflare"],
        "Akamai": ["x-akamai-transformed", "akamai-signature", "server: akamai"],
        "AWS WAF": ["x-amzn-waf-request-id", "x-amz-id-2"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "Imperva": ["x-imperva-id", "x-incap-client-ip", "x-cdn"],
        "F5 BIG-IP": ["x-frame-options: deny", "x-ua-compatible", "server: big-ip"],
        "ModSecurity": ["server: mod_security", "x-mod-security"],
        "Nginx WAF": ["x-nginx-waf", "server: nginx-waf"],
        "360 WAF": ["x-360waf", "x-waf-protection: 360"],
        "Baidu Cloud WAF": ["x-bce-waf", "server: baidu"],
        "Azure WAF": ["x-azure-ref", "x-ms-request-id"]
    },
    "content": {
        "Cloudflare": ["cloudflare", "ray id:", "attention required! cloudflare"],
        "Akamai": ["akamai", "akamai edge platform"],
        "Sucuri": ["sucuri web application firewall", "sucuri cloudproxy"],
        "Imperva": ["incapsula incident id", "imperva"],
        "F5 BIG-IP": ["request rejected by big-ip", "f5 network firewall"],
        "ModSecurity": ["mod_security", "owasp modsecurity core rule set"],
        "WebKnight": ["webknight application firewall", "blocked by webknight"],
        "Nginx WAF": ["nginx waf", "ngx_http_waf_module"],
        "Safe3 WAF": ["safe3waf", "safe3 web application firewall"],
        "360 WAF": ["360 web application firewall", "360waf"],
        "Barracuda": ["barracuda networks", "request blocked by barracuda"],
        "Citrix NetScaler": ["netscaler", "citrix application firewall"]
    },
    "status_codes": {
        "Cloudflare": [403, 406, 503],
        "Akamai": [403, 429],
        "Imperva": [406, 429],
        "Sucuri": [403, 406]
    }
}

# 分阶段测试Payload
TEST_PAYLOADS = {
    "light": [
        "' OR 1=1--",
        "<script>alert(1)</script>",
        "../../etc/passwd",
        "?id=1 AND 1=1"
    ],
    "medium": [
        "1'; DROP TABLE users--",
        "union select 1,version(),3--",
        "<img src=x onerror=alert(1)>",
        "| ls /",
        "; cat /etc/passwd",
        "../windows/system32/drivers/etc/hosts",
        "/.git/config",
        "?user=admin'--"
    ],
    "deep": [
        "' UNION SELECT 1,CONCAT(version(),user(),database()),3--",
        "<svg onload=alert('xss')>",
        "<iframe src=javascript:alert(1)>",
        "|| id; #",
        "?file=php://filter/convert.base64-encode/resource=index.php",
        "?cmd=system('ls')",
        "%27%20OR%201=1%20--",
        "%3Cscript%3Ealert(1)%3C/script%3E"
    ]
}

# 常见的WAF阻断页面关键词
BLOCK_KEYWORDS = [
    "web application firewall", "waf", "security policy",
    "access denied", "forbidden", "request rejected",
    "potential security threat", "invalid request",
    "not allowed", "blocked", "security violation",
    "malicious request", "unauthorized access", "threat detected"
]

class WAFDetector:
    def __init__(self, url: str, timeout: int = 10, delay: float = 2, 
                 random_delay: bool = False, test_level: str = "medium", 
                 proxy: Optional[str] = None, verbose: bool = False,
                 user_agent: Optional[str] = None, output: Optional[str] = None,
                 follow_redirects: bool = True):
        self.url = url
        self.timeout = timeout
        self.delay = delay
        self.random_delay = random_delay
        self.test_level = test_level
        self.proxy = self._setup_proxy(proxy)
        self.verbose = verbose
        self.output = output
        self.follow_redirects = follow_redirects
        self.headers = {"User-Agent": self._get_user_agent(user_agent)}
        self.normal_response = None
        self.original_length = 0
        self.original_status = 0
        self.results = {
            "target": url,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "has_waf": False,
            "detected_waf": [],
            "blocked_requests": 0,
            "total_requests": 0,
            "confidence": 0.0,  # 0-100的置信度评分
            "test_level": test_level,
            "duration": 0.0  # 测试总时长
        }
        
        # 解析URL
        parsed = urlparse(url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.path = parsed.path if parsed.path else "/"

    def _setup_proxy(self, proxy: Optional[str]) -> Optional[Dict[str, str]]:
        """设置代理配置"""
        if proxy:
            return {"http": proxy, "https": proxy}
        return None

    def _get_user_agent(self, custom_ua: Optional[str]) -> str:
        """获取用户代理，优先使用自定义的"""
        if custom_ua:
            return custom_ua
            
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0"
        ]
        return random.choice(user_agents)

    def _send_request(self, url: str) -> Optional[requests.Response]:
        """发送HTTP请求并处理异常"""
        try:
            if self.verbose:
                print(f"[*] 发送请求到: {url}")
            return requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=self.follow_redirects,
                proxies=self.proxy,
                verify=False
            )
        except requests.exceptions.RequestException as e:
            print(f"[!] 请求错误: {str(e)}")
            return None

    def _establish_baseline(self) -> bool:
        """建立正常请求基准线"""
        print("[*] 建立正常请求基准线...")
        self.normal_response = self._send_request(self.url)
        
        if not self.normal_response:
            print("[!] 无法建立正常连接，无法继续测试")
            return False
            
        self.original_length = len(self.normal_response.content)
        self.original_status = self.normal_response.status_code
        
        print(f"[+] 正常请求基准: 状态码 {self.original_status}, 内容长度 {self.original_length}")
        
        # 检查正常响应中是否有WAF特征
        initial_waf = self._detect_waf_from_response(self.normal_response)
        if initial_waf:
            self.results["has_waf"] = True
            self.results["detected_waf"].extend(initial_waf)
            print(f"[!] 初始检测到可能的WAF: {', '.join(initial_waf)}")
            
        return True

    def _detect_waf_from_headers(self, headers: Dict[str, str]) -> List[str]:
        """从响应头检测WAF"""
        detected = []
        header_str = str(headers).lower()
        
        for waf, sigs in WAF_SIGNATURES["headers"].items():
            for sig in sigs:
                if sig.lower() in header_str:
                    detected.append(waf)
                    break
                    
        return list(set(detected))

    def _detect_waf_from_content(self, content: str) -> List[str]:
        """从响应内容检测WAF"""
        detected = []
        content_lower = content.lower()
        
        for waf, sigs in WAF_SIGNATURES["content"].items():
            for sig in sigs:
                if sig.lower() in content_lower:
                    detected.append(waf)
                    break
                    
        return list(set(detected))

    def _detect_waf_from_status_code(self, status_code: int) -> List[str]:
        """从状态码检测WAF"""
        detected = []
        
        for waf, codes in WAF_SIGNATURES["status_codes"].items():
            if status_code in codes:
                detected.append(waf)
                
        return list(set(detected))

    def _detect_waf_from_response(self, response: requests.Response) -> List[str]:
        """综合分析响应检测WAF"""
        if not response:
            return []
            
        detected = []
        
        # 从各个方面检测
        detected.extend(self._detect_waf_from_headers(response.headers))
        detected.extend(self._detect_waf_from_content(str(response.content)))
        detected.extend(self._detect_waf_from_status_code(response.status_code))
        
        return list(set(detected))

    def _is_blocked(self, response: Optional[requests.Response], payload: str) -> Tuple[bool, List[str]]:
        """判断请求是否被阻断"""
        if not response:
            return True, ["Unknown WAF (连接失败)"]
            
        detected_waf = self._detect_waf_from_response(response)
        is_blocked = False
        
        # 检查状态码变化
        if response.status_code != self.original_status:
            is_blocked = True
        
        # 检查内容长度显著变化
        content_length_change = abs(len(response.content) - self.original_length)
        if content_length_change > max(100, self.original_length * 0.3):  # 变化超过100字节或30%
            is_blocked = True
        
        # 检查阻断关键词
        content = str(response.content).lower()
        for keyword in BLOCK_KEYWORDS:
            if keyword in content:
                is_blocked = True
                break
                
        return is_blocked, detected_waf

    def _get_delay(self) -> float:
        """获取请求延迟时间，支持随机延迟"""
        if self.random_delay:
            # 在指定延迟的0.5-1.5倍之间随机
            return self.delay * (0.5 + random.random())
        return self.delay

    def run_tests(self) -> Dict:
        """运行WAF检测测试"""
        start_time = time.time()
        
        # 先建立基准线
        if not self._establish_baseline():
            self.results["duration"] = time.time() - start_time
            self._save_results()
            return self.results
            
        # 根据测试级别选择payload
        payloads = []
        if self.test_level == "full":
            payloads = TEST_PAYLOADS["light"] + TEST_PAYLOADS["medium"] + TEST_PAYLOADS["deep"]
        elif self.test_level in TEST_PAYLOADS:
            payloads = TEST_PAYLOADS[self.test_level]
        
        print(f"[*] 开始{self.test_level}级别测试，共{len(payloads)}个payload")
        
        # 发送测试payload
        for payload in payloads:
            self.results["total_requests"] += 1
            
            # 构建测试URL
            if "?" in self.path:
                test_url = f"{self.base_url}{self.path}&test={payload}"
            else:
                test_url = f"{self.base_url}{self.path}?test={payload}"
            
            # 处理特殊路径测试
            if payload.startswith("/"):
                test_url = urljoin(self.base_url, payload)
            
            if self.verbose:
                print(f"\n[*] 测试URL: {test_url}")
            else:
                print(f"\n[*] 测试URL: {test_url[:80]}...")
                
            response = self._send_request(test_url)
            
            # 判断是否被阻断
            is_blocked, detected_waf = self._is_blocked(response, payload)
            
            # 更新结果
            if is_blocked:
                self.results["blocked_requests"] += 1
                status_code = response.status_code if response else "连接失败"
                print(f"[!] 可能被阻断 - Payload: {payload[:30]}... - 状态码: {status_code}")
                
                if detected_waf:
                    self.results["detected_waf"].extend(detected_waf)
                    print(f"[!] 检测到可能的WAF: {', '.join(detected_waf)}")
            
            else:
                print(f"[+] 未被阻断 - Payload: {payload[:30]}...")
            
            # 添加延迟避免触发速率限制
            delay = self._get_delay()
            if self.verbose:
                print(f"[*] 等待 {delay:.2f} 秒...")
            time.sleep(delay)
        
        # 处理结果
        self.results["detected_waf"] = list(set(self.results["detected_waf"]))
        self.results["has_waf"] = self.results["has_waf"] or self.results["blocked_requests"] > 0
        
        # 计算置信度
        if self.results["has_waf"]:
            block_rate = self.results["blocked_requests"] / self.results["total_requests"]
            self.results["confidence"] = min(100, 30 + block_rate * 70)  # 基础30分 + 阻断率评分
            if self.results["detected_waf"]:
                self.results["confidence"] += 10  # 有明确识别加10分
                self.results["confidence"] = min(100, self.results["confidence"])
        
        # 计算测试时长
        self.results["duration"] = time.time() - start_time
        
        # 保存结果
        self._save_results()
        
        return self.results

    def _save_results(self):
        """保存结果到文件"""
        if self.output:
            try:
                with open(self.output, 'w') as f:
                    json.dump(self.results, f, indent=2)
                print(f"\n[+] 测试结果已保存到 {self.output}")
            except Exception as e:
                print(f"[!] 保存结果失败: {str(e)}")

    def print_results(self):
        """打印格式化的结果"""
        print("\n" + "="*60)
        print(f"目标URL: {self.results['target']}")
        print(f"测试时间: {self.results['timestamp']}")
        print(f"测试级别: {self.results['test_level']}")
        print(f"测试时长: {self.results['duration']:.2f}秒")
        print(f"总请求数: {self.results['total_requests']}")
        print(f"被阻断请求数: {self.results['blocked_requests']}")
        print(f"WAF存在: {'是' if self.results['has_waf'] else '否'}")
        print(f"检测置信度: {self.results['confidence']:.1f}%")
        
        if self.results["detected_waf"]:
            print(f"检测到的WAF类型: {', '.join(self.results['detected_waf'])}")
        else:
            if self.results["has_waf"]:
                print("检测到WAF，但无法识别具体类型")
        
        print("="*60 + "\n")

def main():
    # 忽略SSL警告
    requests.packages.urllib3.disable_warnings()
    
    # 打印Logo
    print(LOGO)
    
    parser = argparse.ArgumentParser(
        description="高级WAF探测工具，用于检测目标网站是否部署了Web应用防火墙并识别其类型",
        formatter_class=argparse.RawTextHelpFormatter
    )
    # 核心参数
    parser.add_argument("-u", "--url", required=True, help="目标URL，例如: https://example.com")
    
    # 连接参数
    parser.add_argument("-t", "--timeout", type=int, default=10, 
                      help="请求超时时间(秒，默认: 10)")
    parser.add_argument("-d", "--delay", type=float, default=2, 
                      help="请求之间的延迟(秒，默认: 2)")
    parser.add_argument("-r", "--random-delay", action="store_true", 
                      help="使用随机延迟，在指定延迟的0.5-1.5倍之间波动")
    parser.add_argument("-p", "--proxy", 
                      help="使用代理，例如: http://127.0.0.1:8080")
    parser.add_argument("--no-redirects", action="store_false", dest="follow_redirects", 
                      help="不跟随重定向")
    
    # 测试参数
    parser.add_argument("-l", "--level", choices=["light", "medium", "deep", "full"], 
                      default="medium", help="测试级别:\n  light: 轻量测试(4个payload)\n  medium: 中等测试(8个payload)\n  deep: 深度测试(8个payload)\n  full: 完整测试(所有payload)")
    parser.add_argument("-a", "--user-agent", 
                      help="自定义User-Agent字符串")
    
    # 输出参数
    parser.add_argument("-v", "--verbose", action="store_true", 
                      help="详细输出模式")
    parser.add_argument("-o", "--output", 
                      help="将结果保存到JSON文件，例如: results.json")
    
    args = parser.parse_args()
    
    print(f"[*] 开始对 {args.url} 进行WAF探测...")
    detector = WAFDetector(
        url=args.url,
        timeout=args.timeout,
        delay=args.delay,
        random_delay=args.random_delay,
        test_level=args.level,
        proxy=args.proxy,
        verbose=args.verbose,
        user_agent=args.user_agent,
        output=args.output,
        follow_redirects=args.follow_redirects
    )
    
    results = detector.run_tests()
    detector.print_results()

if __name__ == "__main__":
    main()
    
