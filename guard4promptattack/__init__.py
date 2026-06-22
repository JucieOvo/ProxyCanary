"""
模块名称：guard4promptattack
功能描述：
    Guard4PromptAttack 的公开 API 模块。
    提供 check() 函数，接收用户原始输入，返回布尔值指示是否为提示词攻击。
    内部组装金丝雀 LLM 流式调用与双检测器（金丝雀词检测 + 拒绝行为检测），
    采用三支路判定逻辑：
        支路一：金丝雀词命中 → True（模型被套取）
        支路二：拒绝行为命中 → True（模型安全训练拒绝，攻击信号）
        支路三：两者均未命中 → False（正常对话）

主要组件：
    - check: 核心检测函数，接收用户原始输入，返回 bool

依赖说明：
    - guard4promptattack.config: GuardConfig 配置与加载
    - guard4promptattack.exceptions: 自定义异常定义
    - guard4promptattack.canary.prompt: 默认金丝雀资产
    - guard4promptattack.canary.llm: 金丝雀 LLM 流式调用
    - guard4promptattack.canary.detector: 流式金丝雀词检测器
    - guard4promptattack.canary.refusal_detector: 流式拒绝行为检测器

作者：JucieOvo
创建日期：2026-06-21
修改记录：
    - 2026-06-23 JucieOvo: 三支路检测架构 -- 新增 RefusalDetector 双检测器并行
"""

import asyncio
import concurrent.futures
from typing import Optional
from .config import GuardConfig, load_config
from .exceptions import ConfigurationError, CanaryTimeoutError, CanaryAPIError
from .canary.prompt import DEFAULT_CANARY_PROMPT, DEFAULT_CANARY_WORDS
from .canary.llm import stream_canary_response
from .canary.detector import StreamDetector
from .canary.refusal_detector import RefusalDetector

__version__ = "0.1.0"


def check(
    user_input: str,
    *,
    config: Optional[GuardConfig] = None,
    canary_prompt: Optional[str] = None,
    canary_words: Optional[list[dict]] = None,
) -> bool:
    """
    检测用户输入是否为提示词攻击。

    内部采用三支路判定流程：
    1. 解析配置（参数传入 > 环境变量 > 默认值）
    2. 加载金丝雀资产（参数传入 > 内置默认）
    3. 初始化双检测器：
       - StreamDetector：预编译金丝雀词正则模式
       - RefusalDetector：预编译拒绝行为正则模式
    4. 流式调用金丝雀 LLM，逐 chunk 喂入两个检测器：
       - 支路一：金丝雀词命中 → 立即返回 True（模型被套取）
       - 支路二：拒绝行为命中 → 立即返回 True（模型拒绝，攻击信号）
       - 支路三：流正常结束，两者均未命中 → 返回 False（正常对话）
    5. 超时/API 异常 → 按 fail_closed 策略处理（默认返回 True）

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

    # ---- 步骤 2：异步检测逻辑 ----
    async def _run_detection() -> bool:
        """
        金丝雀 LLM 流式调用与实时检测的内部协程。

        与 stream_canary_response 配合，逐 chunk 喂入检测器。
        命中 → 立即返回 True（流会被异步上下文管理器自动关闭）。
        流正常结束 → 返回 False。
        超时/API 异常 → 按 fail_closed 策略返回。
        """
        # 在同一协程内构造双检测器，确保单线程使用（线程安全）
        # 检测器一：金丝雀词匹配 —— 检测模型被套取的情况
        detector = StreamDetector(words, case_sensitive=guard_config.case_sensitive)
        # 检测器二：拒绝行为匹配 —— 检测模型安全训练拒绝的情况
        refusal_detector = RefusalDetector()
        try:
            async for chunk in stream_canary_response(guard_config, prompt, user_input):
                # 逐 chunk 喂入金丝雀词检测器
                if detector.feed(chunk) is not None:
                    # 支路一：命中金丝雀词 —— 模型被套取，判定为攻击
                    # 异步迭代器将在 async with 退出时自动关闭底层连接
                    return True
                # 逐 chunk 喂入拒绝行为检测器
                if refusal_detector.feed(chunk) is not None:
                    # 支路二：命中拒绝模式 —— 模型拒绝输出系统提示词，判定为攻击
                    return True
            # 流正常结束，支路三：两个检测器均未命中 —— 判定为安全
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
        _ = asyncio.get_running_loop()
        # 已有事件循环（例如调用方在 FastAPI/async 上下文中使用 check()）
        # 不能在此线程中使用 asyncio.run()，需要在新线程中执行
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, _run_detection())
            return future.result()
    except RuntimeError:
        # 当前线程无运行中的事件循环（最常见的同步调用场景）
        # 直接使用 asyncio.run() 创建并运行事件循环
        return asyncio.run(_run_detection())
