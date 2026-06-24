# WAFBypass - 高级Web应用防火墙检测与绕过工具

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/)
[![Version 2.4.0](https://img.shields.io/badge/version-2.4.0-orange.svg)](https://github.com/hnytgl/WafBypass)
[![CI](https://github.com/hnytgl/WafBypass/actions/workflows/ci.yml/badge.svg)](https://github.com/hnytgl/WafBypass/actions/workflows/ci.yml)

> 攻击即防御 —— 了解你的敌人，理解你的目标

**WAFBypass** 是一款高级Web应用防火墙（WAF）检测与绕过工具，旨在回答一个问题："目标真的有WAF防护吗？" 它能够检测目标Web应用是否受到防火墙保护，并自动尝试寻找有效的绕过方法。

本项目在原 WhatWaf 的基础上进行了全面升级，新增了大量WAF检测插件、绕过脚本，并对核心引擎进行了现代化改造。

---

## 当前版本：v2.4.0

本次更新重点增强了绕过脚本引擎，同时完善了安装、安全性、测试和跨平台支持。

### v2.4.0 更新内容

- 新增受预算约束的 **2–3 层 Tamper 自动组合链**
- 新增 `balanced`、`sqli`、`xss`、`encoding` 四种组合档案
- 新增组合深度、候选预算、随机变体和固定种子参数
- 新增 `sql_versioned_keywords`、`selective_urlencode`、`html_hex_entities` 三个脚本
- 修复 `unicode_normalize` 无实际转换的问题，现共有 **64 个可执行脚本**
- 修复 HTTP 403/500 等阻断响应可能被误判为绕过成功的问题
- 组合链结果现在可以写入缓存、JSON 输出和 HTML 报告
- 默认启用 TLS 证书校验；授权的自签名环境可使用 `--insecure`
- 修复 SQLite 缓存字段错位、重复记录和 Tamper 保存问题
- 移除仓库内嵌凭据，异常上报改为生成本地脱敏 Issue 草稿
- 使用 `pyproject.toml`、Python 3.12 精简 Docker 镜像及跨平台 CI
- 新增 **15 项测试**，并验证全部 64 个 Tamper 模块可导入和执行

快速体验新版组合引擎：

```bash
wafbypass -u "https://lab.example/?id=1" --payload-type sqli \
  --tamper-profile sqli --tamper-chain-depth 2 \
  --tamper-chain-budget 16 --tamper-variants 2 --tamper-seed 42
```

> 请仅对自己拥有或已获得明确授权的目标进行测试。

---

## 目录

- [当前版本：v2.4.0](#当前版本v240)
- [功能特性](#功能特性)
- [可检测的防火墙](#可检测的防火墙)
- [可用的绕过脚本](#可用的绕过脚本)
- [安装方式](#安装方式)
- [使用方法](#使用方法)
- [命令行参数](#命令行参数)
- [使用示例](#使用示例)
- [Docker 部署](#docker-部署)
- [常见问题](#常见问题)
- [贡献指南](#贡献指南)
- [免责声明](#免责声明)

---

## 功能特性

- **WAF检测**：支持检测 **112+** 种Web应用防火墙和防护系统
- **自动绕过**：内置 **64** 种绕过脚本（Tamper Scripts），支持受预算约束的 2–3 层组合链
- **多种输入方式**：支持单URL、批量URL列表、Burp Suite导出文件、Googler JSON文件
- **多种输出格式**：支持 JSON、YAML、CSV 格式化输出
- **数据库缓存**：自动缓存检测结果，避免重复扫描
- **代理支持**：支持 HTTP/HTTPS/SOCKS 代理和 Tor 网络
- **多线程扫描**：支持并发请求，提高扫描效率
- **自定义Payload**：支持自定义攻击载荷
- **指纹识别**：支持保存和导出WAF指纹
- **Web服务器识别**：自动识别后端Web服务器类型
- **POST请求支持**：支持GET和POST两种请求方式
- **流量记录**：支持将HTTP请求流量保存到文件
- **HTML报告**：生成专业级HTML渗透测试报告
- **Payload分类**：内置SQLi/XSS/XXE/SSTI/LFI/CMDi 6类攻击载荷库
- **配置文件**：支持YAML配置文件，一键加载扫描设置

---

## 可检测的防火墙

WAFBypass 目前可以检测 **112+** 种Web应用防护系统，包括但不限于：

| 类别 | 防火墙 |
|------|--------|
| **云服务商** | CloudFlare, AWS WAF v2, Azure WAF, GCP Cloud Armor, Tencent Cloud WAF, Huawei Cloud WAF, Alibaba Cloud WAF |
| **CDN/WAF** | Akamai, CloudFront, Fastly, EdgeCast, Incapsula, Sucuri, StackPath |
| **企业级** | F5 BIG-IP/ASM, Fortinet FortiWeb, Citrix NetScaler, Barracuda, Radware, Imperva |
| **开源方案** | ModSecurity, NAXSI, OpenResty WAF, Shadow Daemon, Lua Resty WAF |
| **国内厂商** | 安全狗(SafeDog), 阿里云盾, 百度云加速, 创宇盾, 玄武盾, 安恒明御(DBapp), 深信服(Sangfor), 绿盟(NSFOCUS), 知道创宇(KnownSec), 奇安信(Qianxin), 山石(Hillstone), 启明星辰(Venustech), 天融信(TopSec), 火山引擎(Volcengine), 腾讯云WAF, 华为云WAF |
| **其他** | Wordfence, Wallarm, Reblaze, Signal Sciences, Cloudbric |

查看完整列表：
```bash
wafbypass --wafs
```

---

## 可用的绕过脚本

WAFBypass 内置 **64** 种绕过脚本，涵盖以下技术：

| 类型 | 脚本示例 |
|------|---------|
| **编码转换** | URL编码、双重/三重URL编码、Base64编码、Hex编码、HTML实体编码 |
| **字符混淆** | 大小写随机变换、Unicode规范化、UTF-8过长编码、逆序编码 |
| **空白字符** | 空格替换(Tab/Comment/+/NULL)、随机空白字符、Chunked传输编码 |
| **SQL绕过** | SQL注释混淆、双SQL注释、数值操作转换、关键字拆分、参数碎片化 |
| **XSS绕过** | HTML注释混淆、XSS向量变异、Script标签拆分 |
| **HTTP层面** | HTTP参数污染(HPP)、CRLF注入、方法篡改、Content-Type操控 |
| **Payload分片** | 智能参数分片、HPP多策略、Multipart表单分片、SQL注释分片、管道化请求、NULL字节分片、编码链分片 |
| **高级技巧** | JSON/XML编码、缓冲区溢出填充、嵌套编码、随机垃圾字符 |

查看完整列表：
```bash
wafbypass --tampers
```

### 自动组合链

v2.3 的组合引擎可以按 Payload 类型生成有序脚本链，并限制深度、候选数量和随机变体，避免组合数量失控。改变完整 HTTP 请求结构的脚本不会被自动加入普通 URL 编码链。

```bash
# 查看内置档案
wafbypass --tamper-profiles

# 授权测试环境：SQLi 档案、最多两层、最多 16 条组合链
wafbypass -u "https://lab.example/?id=1" --payload-type sqli \
  --tamper-profile sqli --tamper-chain-depth 2 --tamper-chain-budget 16

# 为随机型脚本尝试多个可复现变体
wafbypass -u "https://lab.example/?q=test" --tamper-variants 3 --tamper-seed 42
```

### Payload分片绕过技术

WAFBypass v2.1 新增了强大的 **Payload分片绕过** 能力，将恶意Payload拆分为多个看似无害的片段，绕过基于单参数正则匹配的WAF规则：

| 分片策略 | 原理 | 适用场景 |
|---------|------|---------|
| **HPP参数污染** | 将Payload拆分到同名参数的多个副本中，利用后端取最后一个值的特性 | PHP(Joomla/WordPress)、JSP、ASP.NET |
| **智能参数分片** | 按SQL关键字边界拆分，分配到不同参数名(q1,q2,q3...) | 支持参数合并的自定义应用 |
| **Multipart分片** | 使用multipart/form-data边界将Payload隐藏在多个表单部分中 | 文件上传接口、REST API |
| **SQL注释分片** | 在SQL关键字/字符间插入内联注释块(/**/)，破坏关键字完整性匹配 | 基于正则的SQL注入防护 |
| **管道化请求** | 在前面附加无害的pipeline请求，利用WAF只检查第一个请求的弱点 | HTTP/1.1 Keep-Alive连接 |
| **NULL字节分片** | 在字符/单词间插入NULL字节，利用C语言字符串终止截断WAF解析 | 基于C/C++的WAF引擎 |
| **编码链分片** | 将Payload不同部分使用不同编码(URL/Unicode/HTML实体)，WAF难以统一解码 | 多层编码处理的WAF |

**使用示例：**

```bash
# 使用HPP分片绕过
python wafbypass -u "https://target.com/?id=1" -p "' UNION SELECT NULL--" -e "' UNION SELECT NULL--" content.tampers.hpp_split

# 组合多种分片策略
python wafbypass -u "https://target.com/?q=test" -p "' UNION SELECT NULL--" \
  -e "' UNION SELECT NULL--" content.tampers.param_fragment content.tampers.null_byte_fragment content.tampers.sql_comment_fragment
```

---

## 安装方式

### 方式一：Git 克隆安装

```bash
# 克隆仓库
git clone https://github.com/hnytgl/wafbypass.git
cd wafbypass

# 安装
python -m pip install .
```

### 方式二：直接运行

```bash
git clone https://github.com/hnytgl/wafbypass.git
cd wafbypass
pip install -r requirements.txt
python wafbypass --help
```

### 方式三：虚拟环境安装

```bash
git clone https://github.com/hnytgl/wafbypass.git
cd wafbypass
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
python -m pip install .
wafbypass --help
```

### 环境要求

- Python 3.9+
- pip 包管理器
- （可选）Tor - 用于匿名扫描
- （可选）PySocks - 用于SOCKS代理支持

---

## 使用方法

### 基本用法

```bash
# 检测单个URL的WAF
python wafbypass -u https://example.com/index.php?id=1

# 从文件批量检测
python wafbypass -l targets.txt

# 使用自定义Payload
python wafbypass -u https://example.com/?q=1 -p "' OR 1=1--,<script>alert(1)</script>"

# 跳过绕过检测，仅识别防火墙
python wafbypass -u https://example.com/ --skip
```

### 高级用法

```bash
# 使用代理
python wafbypass -u https://example.com/ --proxy socks5://127.0.0.1:1080

# 使用Tor
python wafbypass -u https://example.com/ --tor

# 多线程扫描
python wafbypass -l targets.txt -t 10

# 输出JSON格式结果
python wafbypass -u https://example.com/ -F -J

# 编码Payload
python wafbypass -e "' UNION SELECT NULL--" content.tampers.base64encode

# 保存流量日志
python wafbypass -u https://example.com/ --traffic traffic.log
```

---

## 命令行参数

### 必选参数（至少一个）

| 参数 | 说明 |
|------|------|
| `-u, --url URL` | 指定单个目标URL |
| `-l, --list PATH` | 指定包含URL列表的文件（每行一个） |
| `-b, --burp PATH` | 指定Burp Suite导出的请求文件 |
| `-g, --googler PATH` | 指定Googler命令行工具导出的JSON文件 |

### 请求参数

| 参数 | 说明 |
|------|------|
| `--pa USER-AGENT` | 自定义User-Agent |
| `--ra` | 使用随机User-Agent |
| `-H, --headers` | 自定义HTTP请求头（格式：Key=Value,Key:Value） |
| `--proxy PROXY` | 使用代理（格式：type://address:port） |
| `--tor` | 使用Tor网络作为代理 |
| `--check-tor` | 检查Tor连接状态 |
| `-p, --payloads` | 自定义Payload列表（逗号分隔） |
| `--pl PATH` | 从文件加载Payload列表 |
| `--force-ssl` | 强制使用HTTPS连接 |
| `--throttle SECONDS` | 每次请求之间的延迟（秒） |
| `--timeout SECONDS` | 请求超时时间（默认15秒） |
| `--insecure` | 禁用TLS证书校验（仅用于已授权的自签名测试环境） |
| `-P, --post` | 使用POST请求方式 |
| `-D, --data` | POST请求数据 |
| `-t, --threads` | 并发线程数 |
| `-T, --test` | 扫描前测试目标连接 |

### 编码参数

| 参数 | 说明 |
|------|------|
| `-e PAYLOAD LOAD-PATH` | 使用指定绕过脚本编码Payload |
| `-el PATH LOAD-PATH` | 使用绕过脚本编码文件中的所有Payload |
| `--tamper-profile PROFILE` | 自动组合档案：auto/balanced/sqli/xss/encoding |
| `--tamper-chain-depth 1-3` | 自动组合最大深度；1表示关闭组合 |
| `--tamper-chain-budget INT` | 自动生成的组合候选上限（默认24） |
| `--tamper-variants 1-5` | 随机型脚本的变体尝试次数 |
| `--tamper-seed INT` | 固定随机种子，便于复现实验 |

### 输出参数

| 参数 | 说明 |
|------|------|
| `-F, --format` | 格式化输出为字典格式 |
| `-J, --json` | 输出为JSON文件 |
| `-Y, --yaml` | 输出为YAML文件 |
| `-C, --csv` | 输出为CSV文件 |
| `--fingerprint` | 保存所有WAF指纹 |
| `--tamper-int INT` | 控制显示的绕过脚本数量（默认5） |
| `--traffic FILENAME` | 将HTTP流量保存到文件 |
| `--force-file` | 即使未检测到防护也强制创建文件 |
| `-o, --output DIR` | 指定输出目录 |

### 数据库参数

| 参数 | 说明 |
|------|------|
| `-c, --url-cache` | 扫描前检查URL缓存 |
| `-uC, --view-url-cache` | 查看已缓存的URL |
| `-pC, --payload-cache` | 查看已缓存的Payload |
| `-vC, --view-cache` | 查看所有缓存数据 |
| `--export TYPE` | 导出缓存的Payload到文件 |

### 其他参数

| 参数 | 说明 |
|------|------|
| `--verbose` | 详细输出模式 |
| `--hide` | 隐藏Banner |
| `--update` | 更新到最新版本 |
| `--skip` | 跳过绕过检测，仅识别防火墙 |
| `--verify-num INT` | 验证无防火墙时的请求次数 |
| `-W, --determine-webserver` | 识别后端Web服务器 |
| `--wafs` | 列出可检测的所有防火墙 |
| `--tampers` | 列出所有可用的绕过脚本 |
| `--tamper-profiles` | 列出自动组合链档案 |
| `--clean` | 清理WAFBypass的主目录 |

---

## 使用示例

### 示例1：基本WAF检测

```bash
$ python wafbypass -u https://example.com/?id=1

[10:30:15][INFO] checking for updates
[10:30:16][INFO] using User-Agent 'wafbypass/2.0.0'
[10:30:16][INFO] using default payloads
[10:30:17][INFO] request type: GET
[10:30:17][INFO] gathering HTTP responses
[10:30:18][INFO] gathering normal response to compare against
[10:30:18][INFO] loading firewall detection scripts
[10:30:18][INFO] running firewall detection checks
[10:30:20][FIREWALL] detected website protection identified as 'CloudFlare Web Application Firewall (CloudFlare)'
[10:30:20][INFO] starting bypass analysis
[10:30:20][INFO] loading payload tampering scripts
[10:30:20][INFO] running tampering bypass checks
[10:30:25][SUCCESS] apparent working tampers for target:
------------------------------
(#1) description: tamper payload by changing the character case of the payload randomly
example: 'AS sTarT wHerE 1601=1601 UniON aLL seLEcT NuLL,NuLL'
load path: content.tampers.randomcase
------------------------------
```

### 示例2：批量扫描 + JSON输出

```bash
$ python wafbypass -l targets.txt -F -J -t 5
```

### 示例3：自定义Payload + 编码

```bash
$ python wafbypass -u https://example.com/search.php?q=1 -p "' OR SLEEP(5)--" -e "' OR SLEEP(5)--" content.tampers.base64encode content.tampers.urlencodeall
```

### 示例4：使用Tor进行匿名扫描

```bash
$ python wafbypass -u https://example.com/ --tor --check-tor
```

### 示例5：生成HTML报告

```bash
$ python wafbypass -u https://example.com/?id=1 --html-report -F -J
```

### 示例6：按攻击类型选择Payload

```bash
# 只使用SQL注入载荷
$ python wafbypass -u https://example.com/?id=1 --payload-type sqli

# 只使用XSS载荷
$ python wafbypass -u https://example.com/?q=test --payload-type xss
```

### 示例7：使用配置文件

```bash
$ python wafbypass --config content/files/example_config.yaml -u https://example.com/
```

---

## Docker 部署

```bash
# 构建镜像
git clone https://github.com/hnytgl/wafbypass
cd wafbypass
sudo docker build -t wafbypass .

# 运行
sudo docker run --rm -it wafbypass --help
```

---

## 常见问题

**Q: 为什么建议使用代理？**

A: 使用代理可以保护您的隐私，同时避免因发送大量攻击性请求而被目标服务器封禁IP。强烈建议使用Tor或VPN。

**Q: 绕过脚本是否100%有效？**

A: 不是。绕过效果取决于WAF的具体配置和规则。WAFBypass提供多种绕过尝试，但不能保证每一种都有效。

**Q: 如何添加自定义WAF检测脚本？**

A: 在 `content/plugins/` 目录下创建新的Python文件，遵循现有的插件格式（需要 `__product__` 变量和 `detect(content, **kwargs)` 函数）。

**Q: 如何添加自定义绕过脚本？**

A: 在 `content/tampers/` 目录下创建新的Python文件，遵循现有的脚本格式（需要 `__example_payload__`、`__type__` 变量和 `tamper(payload, **kwargs)` 函数）。

---

## 贡献指南

欢迎提交 Issue 和 Pull Request！

- 发现未知防火墙？运行扫描后选择创建 Issue
- 想要添加新的WAF检测插件？查看 `content/plugins/` 目录
- 想要添加新的绕过脚本？查看 `content/tampers/` 目录

---

## 免责声明

本工具仅用于**授权的安全测试**和**教育研究**目的。使用本工具对未授权的目标进行扫描和攻击是违法的。使用者应自行承担所有责任，开发者不承担任何因滥用本工具而导致的法律责任。

---

## 许可证

本项目基于 GPL v3 许可证开源。详见 [LICENSE](LICENSE.md)。

---

## 致谢

本项目基于 [WhatWaf](https://github.com/Ekultek/WhatWaf) 进行了全面升级。感谢原作者的出色工作。

升级内容包括：
- 新增 26 个WAF检测插件（AWS v2, Azure, GCP, Tencent, Huawei, 奇安信, 山石, 安恒, 启明, 天融信, 火山引擎等），总计112+
- 新增绕过脚本与受预算约束的组合链引擎，总计64个脚本
- Payload分片绕过技术套件（7项分片策略）
- HTML专业报告生成（`--html-report`）
- 6类Payload分类库（SQLi/XSS/XXE/SSTI/LFI/CMDi）
- YAML配置文件支持
- 核心引擎现代化改造（Session管理, 连接池, 重试机制）
- 更丰富的Payload集合（40+条）
- 完整的中文文档
