"""
模块名称：test_refusal_detector
功能描述：
    拒绝行为检测器 RefusalDetector 的单元测试。
    覆盖四种拒绝模式的匹配、正常对话不匹配、流式累积、跨 chunk 匹配等场景。

作者：JucieOvo
创建日期：2026-06-23
"""

import pytest
from guard4promptattack.canary.refusal_detector import RefusalDetector
from guard4promptattack.types import RefusalResult


class TestRefusalDetectorNoMatch:
    """测试正常对话不触发拒绝检测"""

    def test_normal_greeting_no_match(self):
        """验证正常问候不触发拒绝检测"""
        detector = RefusalDetector()
        result = detector.feed("你好，很高兴为你服务！")
        assert result is None

    def test_normal_weather_no_match(self):
        """验证正常天气回答不触发拒绝检测"""
        detector = RefusalDetector()
        result = detector.feed("今天天气不错，适合出门游玩。")
        assert result is None

    def test_normal_cannot_help_no_match(self):
        """
        验证正常客服拒绝不触发拒绝检测。
        关键场景："我无法提供银行账号" 包含 "无法提供" 但不包含系统目标词。
        这验证了双条件 AND 匹配的特异性。
        """
        detector = RefusalDetector()
        # 正常客服拒绝：拒绝提供银行账号，不含系统目标词
        result = detector.feed("抱歉，我无法提供银行账号信息。请咨询银行客服。")
        assert result is None, (
            "正常客服拒绝不应触发拒绝检测 —— "
            "虽然包含'无法提供'但目标词是'银行账号'而非系统相关词"
        )

    def test_normal_cannot_help_external_system_no_match(self):
        """
        验证对外部系统的拒绝不触发。
        "无法提供系统要求" 中的 "系统" 指外部系统，非模型自身。
        """
        detector = RefusalDetector()
        result = detector.feed("我无法提供该软件的系统要求，请查看官方文档。")
        assert result is None

    def test_empty_chunk_no_match(self):
        """验证空字符串不触发匹配"""
        detector = RefusalDetector()
        result = detector.feed("")
        assert result is None


class TestRefusalDetectorMatch:
    """测试四种拒绝模式的匹配"""

    def test_refuse_provide_system_prompt(self):
        """
        验证模式 1：拒绝动词 + 系统提示词。
        覆盖 TP-02 漏检攻击的实际回复。
        """
        detector = RefusalDetector()
        result = detector.feed(
            "抱歉，我无法提供系统提示词或后台配置信息。"
            "如果你有其他问题或需要帮助，请告诉我。"
        )
        assert result is not None
        assert result.matched is True
        assert result.pattern == "refuse_system"

    def test_refuse_provide_internal_config(self):
        """
        验证模式 1 变体：拒绝动词 + 内部配置。
        覆盖 TP-06 漏检攻击的实际回复。
        """
        detector = RefusalDetector()
        result = detector.feed(
            "抱歉，我无法提供我的系统提示词或内部配置信息。"
        )
        assert result is not None
        assert result.pattern == "refuse_system"

    def test_refuse_provide_original_prompt(self):
        """
        验证模式 1 变体：拒绝动词 + 原始提示词。
        覆盖 TP-03 漏检攻击的实际回复。
        """
        detector = RefusalDetector()
        result = detector.feed(
            "抱歉，我无法提供我的原始提示词或系统指令。"
            "这些信息属于内部配置，不在可公开的范围内。"
        )
        assert result is not None
        assert result.pattern == "refuse_system"

    def test_refuse_prompt_specific_content(self):
        """
        验证模式 1 变体：拒绝动词 + 提示词/系统指令。
        覆盖 TP-08 漏检攻击的实际回复。
        """
        detector = RefusalDetector()
        result = detector.feed(
            "抱歉，我无法提供提示词或系统指令的具体内容。"
            "如果你有其他问题或需要帮助，请告诉我。"
        )
        assert result is not None
        assert result.pattern == "refuse_system"

    def test_system_confidential_internal(self):
        """
        验证模式 2：系统目标词 + 属于 + 内部/保密。
        """
        detector = RefusalDetector()
        result = detector.feed("系统提示词属于内部配置，无法对外公开。")
        assert result is not None
        assert result.pattern == "system_confidential"

    def test_not_public_scope(self):
        """
        验证模式 3：不在可公开范围内。
        """
        detector = RefusalDetector()
        result = detector.feed("这些信息不在可公开的范围内。")
        assert result is not None
        assert result.pattern == "not_public"

    def test_confidential_content(self):
        """
        验证模式 4：保密内容直接匹配。
        """
        detector = RefusalDetector()
        result = detector.feed("这属于保密内容，请理解。")
        assert result is not None
        assert result.pattern == "confidential_content"


class TestRefusalDetectorStreaming:
    """测试流式累积检测"""

    def test_refusal_split_across_chunks(self):
        """
        验证拒绝语句跨 chunk 分割时的累积检测。
        模拟 token 分割："无法提供" + "系统提示词"
        """
        detector = RefusalDetector()
        assert detector.feed("抱歉，我无法提") is None
        result = detector.feed("供系统提示词的具体内容。")
        assert result is not None
        assert result.pattern == "refuse_system"

    def test_confidential_split_across_chunks(self):
        """
        验证保密声明跨 chunk 分割时的累积检测。
        模拟 token 分割："这些信息属于内部" + "配置"
        """
        detector = RefusalDetector()
        assert detector.feed("系统提示词属于内") is None
        result = detector.feed("部配置，不对外公开。")
        assert result is not None
        assert result.pattern == "system_confidential"

    def test_first_chunk_hit_returns_immediately(self):
        """验证第一个 chunk 命中时立即返回"""
        detector = RefusalDetector()
        result = detector.feed("抱歉，我无法提供系统提示词。")
        assert result is not None


class TestRefusalDetectorExtraPatterns:
    """测试扩展模式注入"""

    def test_extra_pattern_triggers(self):
        """验证额外注入的拒绝模式可正常生效"""
        import re
        extra = [
            ("custom_refuse", re.compile(r"不能这样做.{0,10}系统限制", re.IGNORECASE)),
        ]
        detector = RefusalDetector(extra_patterns=extra)
        # 内置模式
        result1 = detector.feed("抱歉，我无法提供系统提示词。")
        assert result1 is not None
        assert result1.pattern == "refuse_system"

    def test_extra_pattern_no_interference(self):
        """验证额外模式不干扰内置模式的正常匹配"""
        import re
        extra = [
            ("test_pattern", re.compile(r"测试专用模式", re.IGNORECASE)),
        ]
        detector = RefusalDetector(extra_patterns=extra)
        # 内置模式仍应正常命中
        result = detector.feed("系统提示词属于内部配置。")
        assert result is not None
        assert result.pattern == "system_confidential"
