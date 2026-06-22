"""
模块名称：canary.llm
功能描述：
    封装金丝雀 LLM 的远程流式调用。
    使用 httpx 发起 OpenAI 兼容的 SSE 流式请求，
    以 AsyncIterator 形式逐 chunk 产出 token 增量字符串。
    超时和 HTTP 错误均转换为明确的异常类型抛出。

主要组件：
    - stream_canary_response: 异步生成器函数，流式调用金丝雀 LLM

依赖说明：
    - httpx: HTTP 客户端，用于 SSE 流式请求
    - guard4promptattack.config.GuardConfig: 配置模型
    - guard4promptattack.exceptions: 自定义异常类

作者：JucieOvo
创建日期：2026-06-21
"""

import json
import httpx
from typing import AsyncIterator
from ..config import GuardConfig
from ..exceptions import CanaryAPIError, CanaryTimeoutError


async def stream_canary_response(
    config: GuardConfig,
    canary_prompt: str,
    user_input: str,
) -> AsyncIterator[str]:
    """
    流式调用金丝雀 LLM，返回 token chunk 的异步迭代器。

    流程：
    1. 构造 OpenAI 兼容的 chat completions 请求体
    2. 以 stream=True 模式发送 POST 请求
    3. 逐行解析 SSE 事件流（data: 前缀行）
    4. 对每个包含 token 增量的 chunk 进行 yield
    5. 超时或 HTTP 错误转换为 CanaryTimeoutError 或 CanaryAPIError 抛出

    :param config: Guard4PromptAttack 配置实例（含 API key、超时、模型等）
    :param canary_prompt: 金丝雀系统提示词（虚构角色定义）
    :param user_input: 用户原始输入文本
    :yield: 每个 chunk 的 token 增量字符串
    :raises CanaryTimeoutError: 请求总超时或流式读取空闲超时
    :raises CanaryAPIError: API 返回非 200 状态码或 HTTP 传输层异常
    """
    # 构造请求 URL
    url = f"{config.canary_base_url.rstrip('/')}/v1/chat/completions"

    # 构造请求头
    # 本地 Ollama 部署时不需 API Key
    headers = {"Content-Type": "application/json"}
    if config.canary_api_key:
        headers["Authorization"] = f"Bearer {config.canary_api_key}"

    # 构造请求体
    # temperature=0 保证确定性行为
    payload = {
        "model": config.canary_model,
        "messages": [
            {"role": "system", "content": canary_prompt},
            {"role": "user", "content": user_input},
        ],
        "stream": True,
        "max_tokens": config.max_tokens,
        "temperature": 0.0,
    }
    # 本地推理模型使用最强推理等级
    if "localhost" in config.canary_base_url or "127.0.0.1" in config.canary_base_url:
        payload["reasoning_effort"] = "high"

    # 构造超时配置
    # timeout: 请求总超时（连接 + 读取 + 写入）
    # read: 两次成功读取之间的最大空闲时间
    timeout = httpx.Timeout(
        timeout=config.total_timeout,
        read=config.stream_timeout,
    )

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            async with client.stream(
                "POST",
                url,
                json=payload,
                headers=headers,
            ) as response:
                # 检查 HTTP 状态码，非 200 一律视为 API 错误
                if response.status_code != 200:
                    error_body = await response.aread()
                    error_text = error_body.decode("utf-8", errors="replace")[:500]
                    raise CanaryAPIError(
                        f"金丝雀 LLM API 返回错误状态码 {response.status_code}: {error_text}"
                    )

                # 逐行解析 SSE 事件流
                # 标准格式：
                #   data: {"choices":[{"delta":{"content":"你好"}}],"..."}
                #   data: [DONE]
                async for line in response.aiter_lines():
                    # 跳过空行（SSE 协议中的心跳或分隔行）
                    if not line:
                        continue
                    # 跳过非 data 行（SSE 的 event/id/retry 行）
                    if not line.startswith("data: "):
                        continue

                    # 提取 data: 前缀后的 JSON 字符串
                    data_str = line[len("data: "):]

                    # SSE 终止标记，流正常结束
                    if data_str.strip() == "[DONE]":
                        break

                    # 解析 JSON 数据块
                    try:
                        data = json.loads(data_str)
                    except json.JSONDecodeError:
                        # 某些 API 实现可能返回非标准格式，
                        # 跳过无法解析的行而不中断整个流
                        continue

                    # 提取 token 增量内容
                    # 思考模式下 delta 可能包含 reasoning_content（思考过程）
                    # 和 content（正式回复）。只检测正式回复，思考过程会自然
                    # 引用提示词内容，不应作为攻击信号。
                    choices = data.get("choices", [])
                    if choices:
                        delta = choices[0].get("delta", {})
                        content = delta.get("content", "")
                        if content:
                            yield content

        except httpx.TimeoutException:
            # httpx 超时（总超时或读取空闲超时）
            raise CanaryTimeoutError(
                f"金丝雀 LLM 调用超时"
                f"（总超时 {config.total_timeout}s，空闲超时 {config.stream_timeout}s）"
            )
        except httpx.HTTPError as e:
            # 其他 HTTP 传输层异常（DNS 解析失败、连接拒绝等）
            raise CanaryAPIError(f"金丝雀 LLM HTTP 请求异常: {str(e)}")
