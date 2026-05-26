import os
import logging
from dotenv import load_dotenv


# 配置文件
DEBUG=False

load_dotenv()


# 是否启用通知功能
ENABLE_NOTIFY=True

# 通知类型,目前支持飞书(feishu),钉钉(dingtalk),其他可参考飞书模板 template/feishu.json
NOTIFY_TYPE='dingtalk'

# 是否启用GPT功能进行漏洞分析
ENABLE_GPT=True

# GPT模型名称,使用Gemini 2.0 Flash版本
GPT_MODEL='deepseek-ai/DeepSeek-V3'

# 是否启用漏洞信息搜索功能，需启用GPT分析
ENABLE_SEARCH=True

# 是否启用扩展搜索功能
ENABLE_EXTENDED=True

# 是否启用仓库更新检测(基于commit SHA)
ENABLE_UPDATE_CHECK=True

# 是否启用CVE去重推送(同一CVE每天只推送一次)
ENABLE_CVE_DEDUP=True

# 是否推送仓库更新通知(False=只推送新仓库,True=更新也推送)
ENABLE_UPDATE_NOTIFY=False

# GitHub API Token 配置说明:
# 1. GH_TOKEN: 用户手工配置的 Personal Access Token (推荐，5000次/小时)
# 2. GITHUB_TOKEN: GitHub Actions 自动提供的 Token (1000次/小时)
# 3. 未配置: 使用未认证模式 (60次/小时)
# 优先级: GH_TOKEN > GITHUB_TOKEN > None
GITHUB_TOKEN=None

# 数据库URL
DB_URL='sqlite:///vulns.db'

if os.environ.get('DEBUG'):
    DEBUG = os.environ.get('DEBUG')

def get_config(env: str):
    def to_bool(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', '1', 't', 'y', 'yes')
        return bool(value)

    config = {
        "DEBUG": 'DEBUG' if os.environ.get('DEBUG', str(DEBUG)).lower() == 'true' else 'INFO',
        # 通知配置
        'ENABLE_NOTIFY': to_bool(os.environ.get('ENABLE_NOTIFY')) if os.environ.get('ENABLE_NOTIFY') is not None and os.environ.get('ENABLE_NOTIFY') != '' else ENABLE_NOTIFY,
        'NOTIFY_TYPE': os.environ.get('NOTIFY_TYPE') if os.environ.get('NOTIFY_TYPE') else NOTIFY_TYPE,
        'WEBHOOK_URL': os.environ.get('WEBHOOK_URL'),
        # GPT配置
        'ENABLE_GPT': to_bool(os.environ.get('ENABLE_GPT')) if os.environ.get('ENABLE_GPT') is not None and os.environ.get('ENABLE_GPT') != '' else ENABLE_GPT,
        'GPT_SERVER_URL': os.environ.get('GPT_SERVER_URL'),
        'GPT_API_KEY': os.environ.get('GPT_API_KEY'),
        'GPT_MODEL': os.environ.get('GPT_MODEL') if os.environ.get('GPT_MODEL') else GPT_MODEL,
        # Token限制配置 (字符数，约等于tokens * 4)
        'MAX_CVE_INFO_CHARS': int(os.environ.get('MAX_CVE_INFO_CHARS', '1000')),
        'MAX_SEARCH_CHARS': int(os.environ.get('MAX_SEARCH_CHARS', '2000')),
        'MAX_POC_CODE_CHARS': int(os.environ.get('MAX_POC_CODE_CHARS', '3000')),
        'MAX_RESPONSE_TOKENS': int(os.environ.get('MAX_RESPONSE_TOKENS', '2048')),
        'MAX_PROMPT_CHARS': int(os.environ.get('MAX_PROMPT_CHARS', '24000')),
        # 搜索配置
        'ENABLE_SEARCH': to_bool(os.environ.get('ENABLE_SEARCH')) if os.environ.get('ENABLE_SEARCH') is not None and os.environ.get('ENABLE_SEARCH') != '' else ENABLE_SEARCH,
        'SEARXNG_URL': os.environ.get('SEARXNG_URL'),  # 旧版单引擎配置 (已废弃)
        'SEARXNG_URLS': os.environ.get('SEARXNG_URLS'),  # 新版多引擎配置 (逗号分隔)
        # 数据库配置
        'DB_URL': os.environ.get('DB_URL', DB_URL),
        # 扩展搜索配置
        'ENABLE_EXTENDED': to_bool(os.environ.get('ENABLE_EXTENDED')) if os.environ.get('ENABLE_EXTENDED') is not None and os.environ.get('ENABLE_EXTENDED') != '' else ENABLE_EXTENDED,
        # 更新检测配置
        'ENABLE_UPDATE_CHECK': to_bool(os.environ.get('ENABLE_UPDATE_CHECK')) if os.environ.get('ENABLE_UPDATE_CHECK') is not None and os.environ.get('ENABLE_UPDATE_CHECK') != '' else ENABLE_UPDATE_CHECK,
        # CVE去重推送配置
        'ENABLE_CVE_DEDUP': to_bool(os.environ.get('ENABLE_CVE_DEDUP')) if os.environ.get('ENABLE_CVE_DEDUP') is not None and os.environ.get('ENABLE_CVE_DEDUP') != '' else ENABLE_CVE_DEDUP,
        # 仓库更新推送配置
        'ENABLE_UPDATE_NOTIFY': to_bool(os.environ.get('ENABLE_UPDATE_NOTIFY')) if os.environ.get('ENABLE_UPDATE_NOTIFY') is not None and os.environ.get('ENABLE_UPDATE_NOTIFY') != '' else ENABLE_UPDATE_NOTIFY,
        # GitHub配置 (优先使用 GH_TOKEN，其次 GITHUB_TOKEN)
        'GITHUB_TOKEN': os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or GITHUB_TOKEN,
        # 仓库地址
        'GIT_URL': os.environ.get('GIT_URL', ''),
    }
    return config.get(env, '')
