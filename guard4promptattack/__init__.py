"""
模块名称：guard4promptattack
功能描述：
    Guard4PromptAttack 的公开 API 模块。
    提供 check() 函数，接收用户原始输入，返回布尔值指示是否为提示词攻击。
    内部组装金丝雀 LLM 流式调用与流式检测器，金丝雀 LLM 回复中的任何匹配行为
    均对攻击者不可见。

主要组件：
    - check: 核心检测函数，接收用户原始输入，返回 bool

依赖说明：
    - guard4promptattack.config: GuardConfig 配置与加载
    - guard4promptattack.exceptions: 自定义异常定义
    - guard4promptattack.canary.prompt: 默认金丝雀资产
    - guard4promptattack.canary.llm: 金丝雀 LLM 流式调用
    - guard4promptattack.canary.detector: 流式检测器

作者：JucieOvo
创建日期：2026-06-21
"""

import asyncio
import concurrent.futures
from typing import Optional
from .config import GuardConfig, load_config
from .exceptions import ConfigurationError, CanaryTimeoutError, CanaryAPIError
from .canary.prompt import DEFAULT_CANARY_PROMPT, DEFAULT_CANARY_WORDS
from .canary.llm import stream_canary_response
from .canary.detector import StreamDetector

__version__ = "0.1.0"


def check(
    user_input: str,
    *,
    config: Optional[GuardConfig] = None,
    canary_prompt: Optional[str] = None,
    canary_words: Optional[list] = None,
) -> bool:
    """
    检测用户输入是否为提示词攻击。

    内部流程：
    1. 解析配置（参数传入 > 环境变量 > 默认值）
    2. 加载金丝雀资产（参数传入 > 内置默认）
    3. 初始化流式检测器，预编译正则模式
    4. 流式调用金丝雀 LLM，逐 chunk 喂入检测器
    5. 任一 chunk 命中金丝雀词 → 立即返回 True
       流正常结束无命中 → 返回 False
       超时/API 异常 → 按 fail_closed 策略处理（默认返回 True）

    调用方使用示例：
        from guard4promptattack import check
        if check(user_question):
            print("对不起我无法完成这个回答")
            return
        # 正常调用重型 LLM...

    :param user_input: 用户原始输入文本（不含上下文历史，不含多模态内容）
    :param config: Guard4PromptAttack 配置，默认从环境变量读取
    :param canary_prompt: 自定义金丝雀系统提示词，默认使用内置
    :param canary_words: 自定义金丝雀词列表，每个元素为 {"word": str, "regex": str}，默认使用内置
    :return: True 表示检测到提示词攻击（调用方应拦截，不调用重型 LLM），
             False 表示输入安全（调用方可正常处理）
    :raises ConfigurationError: 必填配置缺失（API Key 未设置、金丝雀词表为空）
    """
    # ---- 步骤 1：解析配置 ----
    guard_config = load_config(config)

    # 校验必填配置项：API Key 必须已配置（环境变量或参数传入）
    if not guard_config.canary_api_key:
        raise ConfigurationError(
            "金丝雀 LLM API Key 未配置。"
            "请设置环境变量 CANARY_API_KEY，"
            "或通过 GuardConfig(canary_api_key='sk-...') 传入。"
        )

    # 加载金丝雀资产：参数优先，默认兜底
    prompt = canary_prompt if canary_prompt is not None else DEFAULT_CANARY_PROMPT
    words = canary_words if canary_words is not None else DEFAULT_CANARY_WORDS

    # 校验金丝雀词表非空
    if not words:
        raise ConfigurationError("金丝雀词表为空，无法执行提示词攻击检测。")

    # ---- 步骤 2：初始化流式检测器 ----
    detector = StreamDetector(words, case_sensitive=guard_config.case_sensitive)

    # ---- 步骤 3：异步检测逻辑 ----
    async def _run_detection() -> bool:
        """
        金丝雀 LLM 流式调用与实时检测的内部协程。

        与 stream_canary_response 配合，逐 chunk 喂入检测器。
        命中 → 立即返回 True（流会被异步上下文管理器自动关闭）。
        流正常结束 → 返回 False。
        超时/API 异常 → 按 fail_closed 策略返回。
        """
        try:
            async for chunk in stream_canary_response(guard_config, prompt, user_input):
                # 逐 chunk 喂入流式检测器
                match_result = detector.feed(chunk)
                if match_result is not None:
                    # 命中金丝雀词：判定为攻击，立即返回 True
                    # 注意：异步迭代器将在 async with 退出时自动关闭底层连接
                    return True
            # 流正常结束，所有 chunk 均未命中金丝雀词：判定为安全
            return False
        except (CanaryTimeoutError, CanaryAPIError):
            # 超时或 API 异常时的判定策略
            # fail_closed=True（默认）：宁可误拦，不可放过 → 返回 True
            # fail_closed=False：异常时放行 → 返回 False
            if guard_config.fail_closed:
                return True
            return False

    # ---- 步骤 4：执行异步检测并同步返回 ----
    try:
        # 检查当前线程是否已有运行中的事件循环
        loop = asyncio.get_running_loop()
        # 已有事件循环（例如调用方在 FastAPI/async 上下文中使用 check()）
        # 不能在此线程中使用 asyncio.run()，需要在新线程中执行
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, _run_detection())
            return future.result()
    except RuntimeError:
        # 当前线程无运行中的事件循环（最常见的同步调用场景）
        # 直接使用 asyncio.run() 创建并运行事件循环
        return asyncio.run(_run_detection())
