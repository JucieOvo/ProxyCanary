"""
模块名称：types
功能描述：
    定义 Guard4PromptAttack 库内部使用的数据类型。
    当前仅包含 MatchResult，用于流式检测器的匹配结果传递。

作者：JucieOvo
创建日期：2026-06-21
"""

from dataclasses import dataclass


@dataclass
class MatchResult:
    """
    金丝雀词匹配结果。

    属性：
        matched (bool): 是否命中金丝雀词，始终为 True（仅在命中时构造此对象）
        word (str): 命中的金丝雀词原文
        match_type (str): 匹配方式，"substring" 表示精确子串匹配，"regex" 表示正则变体匹配
    """
    matched: bool
    word: str = ""
    match_type: str = ""
