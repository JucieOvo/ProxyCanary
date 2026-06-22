"""
模块名称：config
功能描述：
    Guard4PromptAttack 的配置模型与加载逻辑。
    使用 dataclass 定义配置项，通过 load_config() 实现参数 > 环境变量 > 默认值的优先级合并。

主要组件：
    - GuardConfig: 配置 dataclass，包含 8 个字段
    - load_config: 配置加载函数，合并多来源配置值

依赖说明：
    - os.environ: 读取环境变量

作者：JucieOvo
创建日期：2026-06-21
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class GuardConfig:
    """
    Guard4PromptAttack 的完整配置。

    所有字段均有默认值。调用方可创建实例并传入 check() 函数的 config 参数。
    环境变量在 load_config() 中读取，不在 dataclass 初始化时读取。

    属性：
        canary_api_key (str): 金丝雀 LLM 的 API Key，从环境变量 CANARY_API_KEY 读取
        canary_base_url (str): 金丝雀 LLM 的 API 基础 URL
        canary_model (str): 金丝雀 LLM 的模型名称
        total_timeout (float): 请求总超时，单位秒
        stream_timeout (float): SSE 流式读取空闲超时，单位秒
        max_tokens (int): 金丝雀 LLM 回复的最大 token 数
        case_sensitive (bool): 金丝雀词匹配是否区分大小写
        fail_closed (bool): 异常时是否返回 True（拦截）
    """
    canary_api_key: str = ""
    canary_base_url: str = "https://api.deepseek.com"
    canary_model: str = "deepseek-chat"
    total_timeout: float = 5.0
    stream_timeout: float = 2.0
    max_tokens: int = 128
    case_sensitive: bool = False
    fail_closed: bool = True


def load_config(override: Optional[GuardConfig] = None) -> GuardConfig:
    """
    加载配置，按优先级合并多个来源的配置值。

    优先级从高到低：
    1. override 参数中显式传入的值
    2. 环境变量
    3. GuardConfig 类定义的默认值

    如果未提供 override，则创建全新的 GuardConfig 并从环境变量填充。
    如果提供了 override，则直接使用 override 中的值，不做任何环境变量回填。

    :param override: 调用方传入的配置覆盖实例
    :return: 合并后的 GuardConfig 实例
    """
    if override is not None:
        # 直接使用 override 中的值，不做环境变量回填
        # 这确保了"参数 > 环境变量 > 默认值"的优先级契约
        config = GuardConfig(
            canary_api_key=override.canary_api_key,
            canary_base_url=override.canary_base_url,
            canary_model=override.canary_model,
            total_timeout=override.total_timeout,
            stream_timeout=override.stream_timeout,
            max_tokens=override.max_tokens,
            case_sensitive=override.case_sensitive,
            fail_closed=override.fail_closed,
        )
    else:
        # 无 override，使用默认值并从环境变量填充
        config = GuardConfig(
            canary_api_key=os.environ.get("CANARY_API_KEY", ""),
        )

    return config
