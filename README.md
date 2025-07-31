# WAF_Detector
一款轻量高效的 Web 应用防火墙（WAF）探测工具，可检测目标网站是否部署 WAF 并识别其类型，支持多种自定义参数以适应不同测试场景。
## 注意事项
1. 仅用于合法授权的安全测试，未经授权检测他人网站可能违反法律
2. 频繁请求可能触发目标网站的防护机制，建议合理设置延迟
3. 部分WAF可能采用动态特征，结果仅供参考，需结合人工验证

```
                     _     _     __          __
     ____ ___  _____| |   | |    \ \        / /
    / __ `__ \/ ___/ |   | |     \ \  /\  / / 
   / / / / / / /   | |___| |___   \ \/  \/ /  
  /_/ /_/ /_/_/    |_____|_____|   \  /\  /   
                                    \/  \/    
                         Web Application Firewall Detector
```


## 工具特点
- 多维度检测：结合响应头、内容、状态码综合判断WAF存在性
- 分级测试：提供轻量/中等/深度/完整四种测试级别，平衡效率与准确性
- 灵活定制：支持自定义User-Agent、代理、延迟等参数，模拟真实请求
- 结果导出：可将检测结果保存为JSON文件，便于后续分析
- 隐蔽性优化：支持随机延迟，降低被WAF识别为扫描行为的概率


## 适用环境
- **系统**：Kali Linux 2025（推荐）、Ubuntu 22.04+、Debian 12+
- **Python版本**：3.9+


## 安装步骤

1. 克隆仓库到本地
   ```bash
   git clone https://github.com/AverillCN/WAF_Detector.git
   cd waf-detector
   ```

2. 安装依赖（Kali Linux 2025版）
   ```bash
   # 更新软件包列表
   sudo apt update

   # 安装Python及依赖库（若已预装可跳过）
   sudo apt install -y python3 python3-pip
   pip3 install requests
   ```


## 使用指南

### 基本用法
```bash
# 检测目标网站（默认中等测试级别）
python3 waf_detector.py -u https://example.com
```

### 高级用法
```bash
# 深度测试并显示详细输出
python3 waf_detector.py -u https://example.com -l deep -v

# 使用代理+随机延迟+自定义User-Agent
python3 waf_detector.py -u https://example.com -p http://127.0.0.1:8080 -r -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"

# 不跟随重定向并导出结果到JSON
python3 waf_detector.py -u https://example.com --no-redirects -o results.json
```


## 参数说明
| 参数 | 简写 | 说明 |
|------|------|------|
| `--url` | `-u` | **必填**，目标URL（例如：https://example.com） |
| `--timeout` | `-t` | 请求超时时间（秒，默认：10） |
| `--delay` | `-d` | 请求间隔延迟（秒，默认：2） |
| `--random-delay` | `-r` | 使用随机延迟（在指定延迟的0.5-1.5倍波动） |
| `--proxy` | `-p` | 代理服务器（例如：http://127.0.0.1:8080） |
| `--no-redirects` | - | 不跟随HTTP重定向 |
| `--level` | `-l` | 测试级别（light/medium/deep/full，默认：medium） |
| `--user-agent` | `-a` | 自定义User-Agent字符串 |
| `--verbose` | `-v` | 详细输出模式（显示完整请求信息） |
| `--output` | `-o` | 导出结果到JSON文件（例如：results.json） |
| `--help` | `-h` | 显示帮助信息 |


## 测试级别说明
- `light`：轻量测试（4个基础Payload），适合快速检测
- `medium`：中等测试（8个常见攻击Payload），平衡效率与覆盖度
- `deep`：深度测试（8个复杂编码Payload），适合精准验证
- `full`：完整测试（合并所有Payload），适合全面检测


## 结果解读
- **WAF存在**：根据阻断请求比例和特征匹配判断是否存在WAF
- **检测置信度**：0-100%的评分，越高表示结果越可靠
- **WAF类型**：识别出的具体WAF厂商（如Cloudflare、Akamai等）




---

如有问题或建议，可通过Issue反馈.
