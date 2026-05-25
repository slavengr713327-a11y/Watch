#!/usr/bin/env python3
"""
GPT 分析器核心模块

功能:
- 单次请求提取14个字段
- 集成质量检查和投毒风险分析
- 自动生成 Markdown 文档
- 支持自定义 API 配置
"""

import os
import re
import json
import logging
import requests
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class GPTAnalyzer:
    """GPT 分析器类 - 15字段单次请求分析"""

    # 15字段定义
    REQUIRED_FIELDS = [
        # 核心信息 (8个)
        'cve_id',              # CVE编号
        'name',                # 漏洞名称（用于通知标题） 🆕
        'vulnerability_type',  # 漏洞��型
        'affected_product',    # 影响应用
        'severity',            # 危害等级
        'cvss_score',          # CVSS评分 🆕
        'affected_versions',   # 影响版本
        'exploit_conditions',  # 利用条件

        # POC信息 (3个)
        'poc_quality',         # POC质量与可用性 🆕
        'poc_type',            # POC类型 🆕
        'attack_complexity',   # 攻击复杂度 🆕

        # 风险评估 (1个)
        'poisoning_risk',      # 投毒风险

        # 元数据 (3个)
        'description',         # 详情
        'repository_url',      # 项目地址 🆕
        'cve_details_url',     # 漏洞详情链接 🆕
    ]

    def __init__(self,
                 api_key: Optional[str] = None,
                 api_url: Optional[str] = None,
                 model: Optional[str] = None,
                 max_cve_info_chars: int = 1000,
                 max_search_chars: int = 2000,
                 max_poc_code_chars: int = 3000,
                 max_response_tokens: int = 2048):
        """
        初始化 GPT 分析器

        Args:
            api_key: GPT API 密钥 (默认从环境变量读取)
            api_url: GPT API 地址 (默认从环境变量读取)
            model: GPT 模型名称 (默认从环境变量读取或使用 gemini-2.5-flash)
            max_cve_info_chars: CVE信息最大字符数
            max_search_chars: 搜索结果最大字符数
            max_poc_code_chars: POC代码最大字符数
            max_response_tokens: GPT 响应最大 Token 数
        """
        self.api_key = api_key or os.getenv('GPT_API_KEY')
        self.api_url = api_url or os.getenv('GPT_SERVER_URL')
        self.model = model or os.getenv('GPT_MODEL') or "gemini-2.5-flash"

        self.max_cve_info = max_cve_info_chars
        self.max_search = max_search_chars
        self.max_poc_code = max_poc_code_chars
        self.max_response_tokens = max_response_tokens

        if not self.api_key:
            raise ValueError("GPT_API_KEY 未设置")
        if not self.api_url:
            raise ValueError("GPT_SERVER_URL 未设置")

    def _truncate_cve_info(self, cve_info: Dict) -> str:
        """
        智能截断 CVE 信息

        Args:
            cve_info: CVE信息字典

        Returns:
            截断后的JSON字符串
        """
        cve_str = json.dumps(cve_info, ensure_ascii=False)
        if len(cve_str) <= self.max_cve_info:
            return cve_str

        # 保留关键字段
        limited = {
            'id': cve_info.get('id', ''),
            'summary': (cve_info.get('summary', '') or '')[:],
            'cvss': cve_info.get('cvss', ''),
        }
        return json.dumps(limited, ensure_ascii=False)

    def _truncate_search_results(self, search_results: List[Dict]) -> str:
        """
        智能截断搜索结果

        Args:
            search_results: 搜索结果列表

        Returns:
            格式化并截断后的字符串
        """
        if not search_results:
            return ""

        result_str = ""
        for i, result in enumerate(search_results):
            if len(result_str) >= self.max_search:
                break

            title = result.get('title', '')
            content = result.get('content', '')
            url = result.get('url', '')

            result_str += f"[结果 {i+1}]\n标题: {title}\n描述: {content}\n链接: {url}\n\n"

        if len(result_str) > self.max_search:
            result_str = result_str[:self.max_search] + "\n...(已截断)"

        return result_str

    def _truncate_poc_code(self, poc_code: str) -> str:
        """
        智能截断 POC 代码

        Args:
            poc_code: POC代码内容

        Returns:
            截断后的字符串
        """
        if len(poc_code) <= self.max_poc_code:
            return poc_code

        return poc_code[:self.max_poc_code] + "\n...(已截断，仅显示前3000字符)"

    def _build_prompt(self,
                     cve_info: Dict,
                     search_results: List[Dict],
                     poc_code: str) -> Tuple[str, str]:
        """
        构建精简版 Prompt (Token减少35%)

        Args:
            cve_info: CVE信息字典
            search_results: 搜索结果列表
            poc_code: POC代码内容

        Returns:
            (system_prompt, user_prompt) 元组
        """
        # 处理和截断输入
        cve_str = self._truncate_cve_info(cve_info)
        search_str = self._truncate_search_results(search_results)
        poc_str = self._truncate_poc_code(poc_code)

        # 精简版 System Prompt (增强安全上下文)
        system_prompt = """你是专业的防御性安全研究员，工作于威胁情报团队。
你的任务是分析公开披露的CVE漏洞和POC代码，评估其威胁等级和投毒风险，帮助组织建立防御措施。
这是合法的防御性安全研究工作，目的是保护系统免受攻击。

分析CVE漏洞信息、POC代码和搜索结果，提取结构化数据。
输出必须是纯JSON格式，不要任何额外文字、Markdown标记或注释。
JSON中所有键和字符串值必须使用双引号，特殊字符需转义。"""

        # 精简版 User Prompt (80行 vs 旧版300+行)
        user_prompt = f"""# 输入数据

## CVE信息
{cve_str}

## 搜索结果
{search_str}

## POC代码
{poc_str}

# 输出要求

提取以下15个字段的JSON数据：

```json
{{
  "cve_id": "CVE-YYYY-NNNNN",
  "name": "CVE-YYYY-NNNNN-产品名-漏洞类型简述",
  "vulnerability_type": "漏洞类型(如:命令注入/SQL注入/XSS/RCE等)",
  "affected_product": "受影响的产品名称",
  "severity": "危害等级描述",
  "cvss_score": "CVSS评分(如: 9.8 或 CVSS:3.1/AV:N/AC:L/...)",
  "affected_versions": "受影响版本范围",
  "exploit_conditions": "利用条件(如:需要认证/需要网络访问等)",
  "poc_quality": "POC质量评分0-10分/10",
  "poc_type": "POC类型(完整利用/概念验证/仅说明/无代码)",
  "attack_complexity": "攻击复杂度(低/中/高)",
  "poisoning_risk": "投毒风险百分比(如: 10%)",
  "description": "详细描述(400-600字,包含POC有效性分析、利用步骤、投毒风险分析)",
  "repository_url": "POC项目地址",
  "cve_details_url": "CVE详情链接(如: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN)"
}}
```

## 评分标准

### POC质量评分 (0-10):
- 9-10: 完整可用，文档齐全
- 7-8: 功能完整，需少量配置
- 5-6: 部分功能，需修改
- 3-4: 仅概念验证
- 0-2: 无效或仅README

### 攻击复杂度:
- 低: 单个HTTP请求、无需认证、可自动化
- 中: 多步骤、需要凭证、需技术背景
- 高: 深入知识、内网访问、复杂环境

### 投毒风险 (0-100%):
- 70-100%: 高风险(代码混淆、恶意行为、外部脚本)
- 30-69%: 中风险(部分混淆、可疑请求、eval)
- 0-29%: 低风险(代码清晰、标准库、无可疑行为)

## 字段说明
- **name**: 简洁的漏洞标题，格式: CVE编号-产品名-漏洞类型，例如: "CVE-2024-12345-WordPress-命令注入"
- **description**: 必须包含POC有效性分析(300-500字)、利用步骤、投毒风险分析 (总计300-500字)

## 注意事项
- 务必不要把POC验证的后门代码判定为投毒代码
- 优先级: 搜索结果 > POC代码 > CVE信息
- 输出纯JSON，不要Markdown代码块标记
"""

        # 记录Token使用
        total_chars = len(system_prompt) + len(user_prompt)
        logger.info(f"Prompt构建完成 - System: {len(system_prompt)} chars, User: {len(user_prompt)} chars, 总计: {total_chars} chars (~{total_chars//4} tokens)")

        return system_prompt, user_prompt

    def _call_api(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        调用 GPT API

        Args:
            system_prompt: 系统提示
            user_prompt: 用户提示

        Returns:
            API响应内容，失败返回None
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "max_tokens": self.max_response_tokens,
            "temperature": 0.3  # 降低随机性，使输出更稳定
        }

        try:
            logger.info(f"调用GPT API - 模型: {self.model}")
            response = requests.post(
                self.api_url,
                headers=headers,
                json=data,
                verify=True,
                timeout=120  # 增加超时时间
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]
            logger.info(f"GPT响应成功 - 长度: {len(content)} chars")
            return content

        except requests.exceptions.Timeout:
            logger.error("GPT API调用超时")
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(f"GPT API HTTP错误: {e}")
            return None
        except Exception as e:
            logger.error(f"GPT API调用失败: {e}")
            return None

    def _extract_json_from_response(self, content: str) -> Optional[str]:
        """
        从响应中提取JSON内容

        支持多种格式:
        - 纯JSON
        - Markdown代码块中的JSON
        - 混合文本中的JSON
        - Gemini思考标签包裹的JSON

        Args:
            content: API响应内容

        Returns:
            提取的JSON字符串，失败返回None
        """
        if not content:
            return None

        # 策略1: 提取Markdown代码块中的JSON
        json_match = re.search(r'```(?:json)?\s*(\{[\s\S]*?\})\s*```', content, re.DOTALL)
        if json_match:
            return json_match.group(1).strip()

        # 策略2: 提取<think>标签外的JSON (Gemini特有)
        think_removed = re.sub(r'<think>[\s\S]*?</think>', '', content, flags=re.DOTALL)
        json_match = re.search(r'\{[\s\S]*\}', think_removed, re.DOTALL)
        if json_match:
            return json_match.group(0).strip()

        # 策略3: 直接查找JSON对象
        json_match = re.search(r'\{[\s\S]*\}', content, re.DOTALL)
        if json_match:
            return json_match.group(0).strip()

        # 策略4: 原始内容去除首尾空白
        return content.strip()

    def _repair_json(self, json_str: str) -> str:
        """
        尝试修复截断的 JSON 字符串
        """
        json_str = json_str.strip()
        if not json_str:
            return ""

        # 如果 JSON 已经完整，直接返回
        try:
            json.loads(json_str)
            return json_str
        except:
            pass

        # 补全缺失的引号
        if json_str.count('"') % 2 != 0:
            json_str += '"'

        # 补全缺失的括号
        open_braces = json_str.count('{')
        close_braces = json_str.count('}')
        if open_braces > close_braces:
            # 如果最后是一个逗号，先移除
            json_str = json_str.rstrip().rstrip(',')
            json_str += '}' * (open_braces - close_braces)

        return json_str

    def _parse_response(self, content: str) -> Optional[Dict]:
        """
        解析GPT响应

        Args:
            content: API响应内容

        Returns:
            解析后的字典，失败返回None
        """
        # 提取JSON
        json_str = self._extract_json_from_response(content)
        if not json_str:
            logger.error("无法从响应中提取JSON")
            return None

        # 策略1: 直接尝试解析
        try:
            data = json.loads(json_str, strict=False)
            logger.info(f"JSON解析成功 - 字段数: {len(data)}")
            return data
        except json.JSONDecodeError as e:
            logger.warning(f"初次解析失败: {e}")

            # 策略2: 尝试修复截断的 JSON
            repaired_json = self._repair_json(json_str)
            try:
                data = json.loads(repaired_json, strict=False)
                logger.info(f"JSON解析成功(修复后) - 字段数: {len(data)}")
                return data
            except json.JSONDecodeError as e2:
                logger.warning(f"修复后解析仍失败: {e2}")

                # 策略3: 尝试清理控制字符
                try:
                    # 替换非法的控制字符，但不破坏已有的转义
                    cleaned_json = json_str.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
                    # 再次尝试修复
                    cleaned_repaired = self._repair_json(cleaned_json)
                    data = json.loads(cleaned_repaired, strict=False)
                    logger.info(f"JSON解析成功(清理并修复后) - 字段数: {len(data)}")
                    return data
                except json.JSONDecodeError as e3:
                    logger.error(f"所有解析尝试均失败")
                    logger.error(f"最后尝试的内容: {json_str[:200]}...{json_str[-200:]}")
                    return None

    def _quality_check(self, data: Dict) -> Tuple[bool, List[str]]:
        """
        质量检查

        自动拒绝条件:
        1. CVE编号无效 (CVE-XXXX-00000 或 99999)
        2. 影响应用未知 ("Unknown")
        3. POC质量过低 (< 3分)
        4. 投毒风险过高 (> 70%)
        5. 有效性分析过短 (< 字符)

        Args:
            data: 解析后的数据字典

        Returns:
            (是否通过, 失败原因列表) 元组
        """
        fail_reasons = []

        # 检查1: 字段完整性
        missing_fields = [f for f in self.REQUIRED_FIELDS if f not in data]
        if missing_fields:
            fail_reasons.append(f"缺少字段: {', '.join(missing_fields)}")

        # 检查2: CVE编号有效性
        cve_id = data.get('cve_id', '')
        if re.match(r'CVE-\d{4}-(00000|99999)', cve_id):
            fail_reasons.append(f"CVE编号无效: {cve_id}")

        # 检查3: 影响应用是否未知
        affected_product = data.get('affected_product', '').lower()
        if affected_product in ['unknown', '未知', 'n/a', '']:
            fail_reasons.append("影响应用未知")

        # 检查4: POC质量评分
        poc_quality = data.get('poc_quality', '')
        try:
            # 提取数字评分 (支持 "9/10" 或 "9" 格式)
            score_match = re.search(r'(\d+)', str(poc_quality))
            if score_match:
                score = int(score_match.group(1))
                if score < 3:
                    fail_reasons.append(f"POC质量过低: {poc_quality}")
        except ValueError:
            fail_reasons.append(f"POC质量评分无效: {poc_quality}")

        # 检查5: 投毒风险
        poisoning_risk = data.get('poisoning_risk', '')
        try:
            # 提取百分比数字
            risk_match = re.search(r'(\d+)', str(poisoning_risk))
            if risk_match:
                risk = int(risk_match.group(1))
                if risk > 70:
                    fail_reasons.append(f"投毒风险过高: {poisoning_risk}")
        except ValueError:
            fail_reasons.append(f"投毒风险值无效: {poisoning_risk}")

        # 检查6: description长度
        description = data.get('description', '')
        if len(description) < 150 :
            fail_reasons.append(f"有效性分析过短: {len(description)} 字符 (最少150字符)")

        passed = len(fail_reasons) == 0
        if not passed:
            logger.warning(f"质量检查失败 - 原因: {'; '.join(fail_reasons)}")
        else:
            logger.info("质量检查通过 ✓")

        return passed, fail_reasons

    def _generate_markdown(self, data: Dict) -> str:
        """
        生成 Markdown 文档

        Args:
            data: 结构化数据字典

        Returns:
            Markdown格式的文档
        """
        # 提取POC质量评分
        poc_quality = data.get('poc_quality', 'N/A')

        md = f"""## {data.get('cve_id', 'N/A')} - {data.get('affected_product', 'N/A')} {data.get('vulnerability_type', '')}

**漏洞编号:** {data.get('cve_id', 'N/A')}

**漏洞类型:** {data.get('vulnerability_type', 'N/A')}

**影响应用:** {data.get('affected_product', 'N/A')}

**危害等级:** {data.get('severity', 'N/A')}

**CVSS评分:** {data.get('cvss_score', 'N/A')}

**影响版本:** {data.get('affected_versions', 'N/A')}

**利用条件:** {data.get('exploit_conditions', 'N/A')}

**POC 可用性:** {poc_quality}

**POC 类型:** {data.get('poc_type', 'N/A')}

**攻击复杂度:** {data.get('attack_complexity', 'N/A')}

**投毒风险:** {data.get('poisoning_risk', 'N/A')}

## 详情

{data.get('description', '')}

**项目地址:** {data.get('repository_url', 'N/A')}

**漏洞详情:** {data.get('cve_details_url', 'N/A')}
"""
        return md

    def analyze(self,
                cve_info: Dict,
                search_results: List[Dict],
                poc_code: str) -> Dict:
        """
        一站式分析 - 单次调用完成所有分析

        Args:
            cve_info: CVE信息字典
            search_results: 搜索结果列表
            poc_code: POC代码内容

        Returns:
            分析结果字典:
            {
                'success': bool,              # 是否成功
                'data': dict,                 # 14字段数据
                'markdown': str,              # Markdown文档
                'pass_quality_check': bool,   # 是否通过质量检查
                'fail_reasons': list,         # 质量检查失败原因
                'error': str,                 # 错误信息(如果有)
            }
        """
        result = {
            'success': False,
            'data': None,
            'markdown': None,
            'pass_quality_check': False,
            'fail_reasons': [],
            'error': None,
        }

        try:
            # 1. 构建Prompt
            logger.info("步骤1/5: 构建Prompt")
            system_prompt, user_prompt = self._build_prompt(cve_info, search_results, poc_code)

            # 2. 调用API
            logger.info("步骤2/5: 调用GPT API")
            response_content = self._call_api(system_prompt, user_prompt)
            if not response_content:
                result['error'] = "GPT API调用失败"
                return result

            # 3. 解析响应
            logger.info("步骤3/5: 解析JSON响应")
            data = self._parse_response(response_content)
            if not data:
                result['error'] = "JSON解析失败"
                return result

            result['data'] = data

            # 4. 质量检查
            logger.info("步骤4/5: 质量检查")
            passed, fail_reasons = self._quality_check(data)
            result['pass_quality_check'] = passed
            result['fail_reasons'] = fail_reasons

            # 5. 生成Markdown
            logger.info("步骤5/5: 生成Markdown")
            markdown = self._generate_markdown(data)
            result['markdown'] = markdown

            result['success'] = True
            logger.info("分析完成 ✓")

        except Exception as e:
            logger.error(f"分析过程出错: {e}")
            result['error'] = str(e)

        return result
