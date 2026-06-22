"""
模块名称：exceptions
功能描述：
    定义 Guard4PromptAttack 库的自定义异常类层级。
    所有异常继承自 Guard4PromptAttackError 基类，便于调用方统一捕获。

主要组件：
    - Guard4PromptAttackError: 所有异常的基类
    - ConfigurationError: 配置校验失败
    - CanaryAPIError: 金丝雀 LLM API 调用失败
    - CanaryTimeoutError: 金丝雀 LLM 调用超时

作者：JucieOvo
创建日期：2026-06-21
"""


class Guard4PromptAttackError(Exception):
    """所有 Guard4PromptAttack 异常的基类，调用方可统一捕获"""
    pass


class ConfigurationError(Guard4PromptAttackError):
    """
    配置错误异常。

    触发场景：
    - 金丝雀 LLM API Key 未配置
    - 金丝雀词表为空
    - 其他必填配置项缺失
    """
    pass


class CanaryAPIError(Guard4PromptAttackError):
    """
    金丝雀 LLM API 调用失败异常。

    触发场景：
    - 远程 API 返回非 200 状态码
    - HTTP 传输层异常（连接拒绝、DNS 解析失败等）
    - API 返回的响应格式不符合预期
    """
    pass


class CanaryTimeoutError(Guard4PromptAttackError):
    """
    金丝雀 LLM 调用超时异常。

    触发场景：
    - 请求总耗时超过 total_timeout
    - SSE 流式响应中连续空闲时间超过 stream_timeout
    """
    pass
