# VulnWatchdog - 漏洞情报库

> 🤖 自动化CVE漏洞监控与分析系统
> 📅 最后更新: 2026-05-31
> 📊 已收录: **2212** 个CVE | **7992** 个POC仓库

---

## 🚀 快速开始

### 浏览方式
- 📅 **按年份浏览** - 查看特定年份的CVE漏洞
  - [2026年](2026/README.md) (332 个)
  - [2025年](2025/README.md) (2657 个)
  - [2024年](2024/README.md) (1120 个)
  - [2023年](2023/README.md) (900 个)
  - [2022年](2022/README.md) (647 个)
- 🔍 **按CVE编号查找** - 直接访问 `by-cve/CVE-XXXX-XXXXX.md`
- 📰 **订阅更新** - 见下方订阅方式

### 订阅方式
- 🔔 **GitHub Watch** - 点击右上角 ⭐ Star 和 👁️ Watch 接收更新通知
- 📡 **RSS订阅** - 添加到RSS阅读器:
  ```
  https://github.com/VulnWatchdog/VulnWatchdog/commits.atom
  ```
- 💬 **飞书通知** - Fork后配置Webhook接收实时推送

---

## 📊 数据统计

### 年度分布

| 年份 | 漏洞数量 | 占比 |
|------|---------|------|
| [2026](2026/README.md) | 332 | 15.0% |
| [2025](2025/README.md) | 2657 | 120.1% |
| [2024](2024/README.md) | 1120 | 50.6% |
| [2023](2023/README.md) | 900 | 40.7% |
| [2022](2022/README.md) | 647 | 29.2% |
| [2021](2021/README.md) | 593 | 26.8% |
| [2020](2020/README.md) | 337 | 15.2% |
| [2019](2019/README.md) | 407 | 18.4% |
| [2018](2018/README.md) | 359 | 16.2% |
| [2017](2017/README.md) | 297 | 13.4% |
| [2016](2016/README.md) | 89 | 4.0% |
| [2015](2015/README.md) | 58 | 2.6% |
| [2014](2014/README.md) | 50 | 2.3% |
| [2013](2013/README.md) | 22 | 1.0% |
| [2012](2012/README.md) | 25 | 1.1% |
| [2011](2011/README.md) | 39 | 1.8% |
| [2010](2010/README.md) | 7 | 0.3% |
| [2009](2009/README.md) | 5 | 0.2% |
| [2008](2008/README.md) | 1 | 0.0% |
| [2007](2007/README.md) | 41 | 1.9% |
| [2004](2004/README.md) | 3 | 0.1% |
| [2002](2002/README.md) | 2 | 0.1% |
| [2001](2001/README.md) | 1 | 0.0% |

### 热门CVE Top 10

| CVE编号 | POC仓库数 | 年份 |
|---------|-----------|------|
| [CVE-2025-55182](by-cve/CVE-2025-55182.md) | 185 | 2025 |
| [CVE-2025-29927](by-cve/CVE-2025-29927.md) | 116 | 2025 |
| [CVE-2025-32463](by-cve/CVE-2025-32463.md) | 90 | 2025 |
| [CVE-2021-44228](by-cve/CVE-2021-44228.md) | 57 | 2021 |
| [CVE-2025-24813](by-cve/CVE-2025-24813.md) | 55 | 2025 |
| [CVE-2025-8088](by-cve/CVE-2025-8088.md) | 55 | 2025 |
| [CVE-2024-4577](by-cve/CVE-2024-4577.md) | 53 | 2024 |
| [CVE-2025-53770](by-cve/CVE-2025-53770.md) | 52 | 2025 |
| [CVE-2021-41773](by-cve/CVE-2021-41773.md) | 45 | 2021 |
| [CVE-2025-14847](by-cve/CVE-2025-14847.md) | 41 | 2025 |

---

## 🛠️ 使用说明

### 搜索CVE
```bash
# 按CVE编号查找
cat data/by-cve/CVE-2024-1234.md

# 按年份查找
ls data/2024/

# 搜索关键词
grep -r "RCE" data/2024/
```

### API使用
```python
# 通过GitHub API获取最新CVE
import requests

url = "https://api.github.com/repos/VulnWatchdog/VulnWatchdog/commits"
response = requests.get(url)
latest_commit = response.json()[0]
print(f"最新更新: {latest_commit['commit']['message']}")
```

---

## 📖 相关文档

- [项目主页](../README.md)
- [通知配置](../NOTIFY.md)
- [贡献指南](../README.md#贡献)

---

*本项目由 VulnWatchdog 自动维护 | [GitHub](https://github.com/VulnWatchdog/VulnWatchdog)*
