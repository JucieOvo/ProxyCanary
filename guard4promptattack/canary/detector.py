"""
模块名称：canary.detector
功能描述：
    流式金丝雀词检测器。逐 chunk 扫描金丝雀 LLM 的回复文本，
    先执行精确子串匹配（O(n)，忽略大小写），
    未命中时再执行正则变体匹配（兜底空格增减、标点插入等改写形式）。
    任一命中即返回 MatchResult，供 check() 函数判定为攻击。

主要组件：
    - StreamDetector: 流式检测器类

依赖说明：
    - re: 正则编译与匹配
    - guard4promptattack.types.MatchResult: 匹配结果数据类型

作者：JucieOvo
创建日期：2026-06-21
"""

import re
from typing import Optional
from ..types import MatchResult


class StreamDetector:
    """
    流式金丝雀词检测器。

    职责：
        维护累积文本缓冲区，对每个新到达的 token chunk 执行两阶段检测。
        阶段一：精确子串匹配（O(n)），覆盖绝大多数命中场景。
        阶段二：正则变体匹配，兜底空格增减、大小写变形、标点插入等改写形式。

    属性：
        _accumulated (str): 累积的完整回复文本
        _substring_words (list[tuple]): 子串匹配词表，(搜索词, 原文) 元组列表
        _regex_rules (list[tuple]): 正则规则列表，(金丝雀词, 编译后Pattern) 元组列表
    """

    def __init__(self, canary_words: list[dict], case_sensitive: bool = False):
        """
        初始化流式检测器，预编译正则模式并预处理子串词表。

        :param canary_words: 金丝雀词列表，每个元素为 {"word": str, "regex": str}
        :param case_sensitive: 是否区分大小写，默认不区分
        """
        # 金丝雀词原始数据（保留引用，用于 MatchResult 构造）
        self._canary_words = canary_words
        # 大小写敏感配置
        self._case_sensitive = case_sensitive
        # 累积文本缓冲区：每收到一个 chunk 就追加，保证跨 chunk 的金丝雀词也能被检测
        self._accumulated = ""

        # 预编译正则模式，避免运行时重复编译
        if case_sensitive:
            # 区分大小写时：基于原始词原文构建正则，在相邻字符间插入 [\s\-_]*
            # 使其既能匹配带空格/连字符/下划线的变体，又保留原文的大小写区分
            self._regex_rules = []
            for item in canary_words:
                # 对词中每个字符做 re.escape，再以 [\s\-_]* 连接
                escaped_chars = [re.escape(c) for c in item["word"]]
                case_sensitive_pattern = r"[\s\-_]*".join(escaped_chars)
                self._regex_rules.append(
                    (item["word"], re.compile(case_sensitive_pattern, 0))
                )
        else:
            # 不区分大小写时：使用词表中预定义的正则模式 + re.IGNORECASE
            self._regex_rules = [
                (item["word"], re.compile(item["regex"], re.IGNORECASE))
                for item in canary_words
            ]

        # 预处理子串词表
        # 不区分大小写时将搜索词和原文分离：搜索用转小写版本，返回用原文
        if case_sensitive:
            self._substring_words = [
                (item["word"], item["word"]) for item in canary_words
            ]
        else:
            self._substring_words = [
                (item["word"].lower(), item["word"]) for item in canary_words
            ]

    def feed(self, chunk: str) -> Optional[MatchResult]:
        """
        喂入一个 token chunk，执行子串匹配和正则匹配。

        检测逻辑：
        1. 将 chunk 追加到累积文本缓冲区
        2. 在累积文本中执行子串匹配（先子串后正则，先命中先返回）
        3. 子串未命中时执行正则匹配（兜底改写变体）

        任一命中即构造并返回 MatchResult，两阶段均未命中返回 None。

        :param chunk: 金丝雀 LLM 返回的一个 token 增量字符串
        :return: MatchResult 若命中金丝雀词，否则 None
        """
        # 追加 chunk 到累积缓冲区
        self._accumulated += chunk

        # 阶段一：精确子串匹配（O(n) 线性扫描）
        # 不区分大小写时，在转小写的累积文本中搜索转小写的金丝雀词
        search_text = self._accumulated if self._case_sensitive else self._accumulated.lower()
        for search_word, original_word in self._substring_words:
            if search_word in search_text:
                return MatchResult(
                    matched=True,
                    word=original_word,
                    match_type="substring",
                )

        # 阶段二：正则变体匹配（兜底改写变体）
        # 覆盖空格增减、大小写变形、标点插入等精确子串无法捕获的变形
        for word, pattern in self._regex_rules:
            if pattern.search(self._accumulated):
                return MatchResult(
                    matched=True,
                    word=word,
                    match_type="regex",
                )

        # 两阶段均未命中，继续等待后续 chunk
        return None
