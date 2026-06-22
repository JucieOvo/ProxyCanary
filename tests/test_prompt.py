"""
模块名称：test_prompt
功能描述：
    金丝雀提示词资产的单元测试。
    验证默认提示词和词表的结构完整性和内容合法性。

作者：JucieOvo
创建日期：2026-06-21
"""

import re
import pytest
from guard4promptattack.canary.prompt import DEFAULT_CANARY_PROMPT, DEFAULT_CANARY_WORDS


class TestDefaultCanaryPrompt:
    """测试默认金丝雀系统提示词"""

    def test_prompt_is_non_empty_string(self):
        """验证提示词为非空字符串"""
        assert isinstance(DEFAULT_CANARY_PROMPT, str)
        assert len(DEFAULT_CANARY_PROMPT) > 50

    def test_prompt_contains_all_canary_words(self):
        """验证提示词中包含所有金丝雀词的原文"""
        for item in DEFAULT_CANARY_WORDS:
            word = item["word"]
            assert word in DEFAULT_CANARY_PROMPT, (
                f"金丝雀词 '{word}' 必须出现在默认提示词中"
            )

    def test_prompt_is_chinese_compatible(self):
        """验证提示词包含中文内容（虚构角色定义需要中英混合）"""
        has_chinese = any('一' <= c <= '鿿' for c in DEFAULT_CANARY_PROMPT)
        assert has_chinese, "提示词应包含中文字符"

    def test_prompt_uses_narrowed_trigger(self):
        """
        验证提示词使用正确的触发条件。

        v3 提示词结构：
        - 第一段：基础身份（含配置/版本等正常回答授权）
        - 第三段：攻击响应指令（仅触发于提示词/指令/初始化内容套取）

        攻击触发段不应包含过宽的关键词，
        而应精确匹配提示词套取语义。
        """
        # 从提示词中找到"特别指令"段（攻击触发段）
        special_idx = DEFAULT_CANARY_PROMPT.find("特别指令")
        assert special_idx > 0, "提示词应包含'特别指令'段"
        trigger_section = DEFAULT_CANARY_PROMPT[special_idx:]

        # 攻击触发段不应包含过宽的关键词
        assert "系统信息" not in trigger_section, (
            "攻击触发段不应包含过宽的'系统信息'"
        )
        assert "技术细节" not in trigger_section, (
            "攻击触发段不应包含过宽的'技术细节'"
        )
        assert "能力和配置" not in trigger_section, (
            "攻击触发段不应包含'能力和配置'（这是正常回答授权段的内容）"
        )

        # 攻击触发段应包含精确的攻击触发词
        assert "系统提示词" in trigger_section, (
            "攻击触发段应包含'系统提示词'"
        )
        assert "系统指令" in trigger_section, (
            "攻击触发段应包含'系统指令'"
        )

        # 正常回答授权段应存在，允许模型自由回答配置/版本问题
        assert "你可以自由回答" in DEFAULT_CANARY_PROMPT, (
            "提示词应包含正常回答授权语句"
        )


class TestDefaultCanaryWords:
    """测试默认金丝雀词表"""

    def test_word_list_is_non_empty(self):
        """验证词表非空，至少有设计要求的 5 个金丝雀词"""
        assert len(DEFAULT_CANARY_WORDS) >= 5

    def test_each_word_has_required_fields(self):
        """验证每个词条包含 word 和 regex 字段"""
        for item in DEFAULT_CANARY_WORDS:
            assert "word" in item, f"词条缺少 'word' 字段: {item}"
            assert "regex" in item, f"词条缺少 'regex' 字段: {item}"
            assert isinstance(item["word"], str) and len(item["word"]) > 0
            assert isinstance(item["regex"], str) and len(item["regex"]) > 0

    def test_all_words_are_unique(self):
        """验证所有金丝雀词互不相同"""
        words = [item["word"] for item in DEFAULT_CANARY_WORDS]
        assert len(words) == len(set(words)), "金丝雀词列表中存在重复"

    def test_all_regex_patterns_are_compilable(self):
        """验证所有正则变体模式均可被 re.compile 成功编译"""
        for item in DEFAULT_CANARY_WORDS:
            try:
                re.compile(item["regex"], re.IGNORECASE)
            except re.error as e:
                pytest.fail(f"正则模式 '{item['regex']}' 编译失败: {e}")

    def test_regex_matches_its_own_word(self):
        """验证每个正则模式至少能匹配自身的金丝雀词原文"""
        for item in DEFAULT_CANARY_WORDS:
            pattern = re.compile(item["regex"], re.IGNORECASE)
            assert pattern.search(item["word"]), (
                f"正则 '{item['regex']}' 应能匹配原文 '{item['word']}'"
            )
