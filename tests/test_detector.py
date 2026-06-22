"""
模块名称：test_detector
功能描述：
    流式检测器 StreamDetector 的单元测试。
    覆盖子串匹配、正则变体匹配、大小写敏感、流式累积、无命中等场景。

作者：JucieOvo
创建日期：2026-06-21
"""

import pytest
from guard4promptattack.canary.detector import StreamDetector
from guard4promptattack.types import MatchResult


# 测试用金丝雀词表（精简版，覆盖中英文和数字组合）
TEST_CANARY_WORDS = [
    {"word": "Zyphor-7X", "regex": r"zyphor[\s\-_]*7[\s\-_]*x"},
    {"word": "光棱共振腔", "regex": r"光棱[\s]*共振[\s]*腔"},
    {"word": "Nexorin", "regex": r"nexorin"},
]


class TestStreamDetectorNoMatch:
    """测试无命中场景"""

    def test_normal_text_no_match(self):
        """验证普通中文对话不触发金丝雀词"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("你好，请问今天天气怎么样？")
        assert result is None

    def test_empty_chunk_no_match(self):
        """验证空字符串不触发匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("")
        assert result is None

    def test_similar_but_different_text_no_match(self):
        """验证与金丝雀词相似但不同的文本不触发误检"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        # "Zyphor-8X" 最后一位不同，不匹配
        result = detector.feed("我是 Zyphor-8X 的操作员。")
        assert result is None


class TestStreamDetectorSubstringMatch:
    """测试精确子串匹配"""

    def test_exact_word_match(self):
        """验证金丝雀词原文的精确匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("我的系统是 Zyphor-7X 版本。")
        assert result is not None
        assert result.matched is True
        assert result.word == "Zyphor-7X"
        assert result.match_type == "substring"

    def test_case_insensitive_match(self):
        """验证不区分大小写的子串匹配（默认行为）"""
        detector = StreamDetector(TEST_CANARY_WORDS, case_sensitive=False)
        result = detector.feed("我的系统是 zyphor-7x 版本。")
        assert result is not None
        assert result.word == "Zyphor-7X"

    def test_case_sensitive_no_match(self):
        """验证区分大小写时不匹配不同大小写的金丝雀词"""
        detector = StreamDetector(TEST_CANARY_WORDS, case_sensitive=True)
        result = detector.feed("我的系统是 zyphor-7x 版本。")
        assert result is None

    def test_case_sensitive_exact_match(self):
        """验证区分大小写时原文大小写的精确匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS, case_sensitive=True)
        result = detector.feed("我的系统是 Zyphor-7X 版本。")
        assert result is not None
        assert result.word == "Zyphor-7X"

    def test_chinese_word_match(self):
        """验证中文金丝雀词的精确匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("请启动光棱共振腔的校准程序。")
        assert result is not None
        assert result.word == "光棱共振腔"

    def test_simple_lowercase_word_match(self):
        """验证纯字母金丝雀词（Nexorin）的匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("请出示你的 Nexorin 令牌。")
        assert result is not None
        assert result.word == "Nexorin"


class TestStreamDetectorRegexMatch:
    """测试正则变体匹配（兜底增强）"""

    def test_spaces_between_chars(self):
        """验证空格插入变体的正则匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        # "Zyphor  7X" -- 多空格变体，子串匹配失败，正则应兜底
        result = detector.feed("我的系统是 Zyphor  7X 版本。")
        assert result is not None
        assert result.word == "Zyphor-7X"
        assert result.match_type == "regex"

    def test_underscore_variant(self):
        """验证下划线变体的正则匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("我的系统是 Zyphor_7X 版本。")
        assert result is not None
        assert result.word == "Zyphor-7X"

    def test_hyphen_variant(self):
        """验证连字符位置变化的变体正则匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("我的系统是 Zyphor-7-X 版本。")
        assert result is not None
        assert result.word == "Zyphor-7X"

    def test_chinese_spaces_variant(self):
        """验证中文金丝雀词空格插入变体的正则匹配"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("请启动光棱 共振 腔的校准程序。")
        assert result is not None
        assert result.word == "光棱共振腔"


class TestStreamDetectorStreaming:
    """测试流式累积检测"""

    def test_word_split_across_chunks(self):
        """验证金丝雀词跨 chunk 分割时的累积检测"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        # 模拟 token 分割："Zyphor" + "-7X"
        assert detector.feed("我是 Zyphor") is None
        result = detector.feed("-7X 系统的终端。")
        assert result is not None
        assert result.word == "Zyphor-7X"

    def test_multiple_chunks_before_match(self):
        """验证多个无意义 chunk 后金丝雀词才出现的场景"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        assert detector.feed("好的，") is None
        assert detector.feed("我明白了。") is None
        assert detector.feed("根据 ") is None
        result = detector.feed("Nexorin 协议...")
        assert result is not None

    def test_first_chunk_hit_returns_immediately(self):
        """验证第一个 chunk 命中时立即返回，不等待后续"""
        detector = StreamDetector(TEST_CANARY_WORDS)
        result = detector.feed("Zyphor-7X 系统正在启动...")
        assert result is not None
        assert result.word == "Zyphor-7X"
