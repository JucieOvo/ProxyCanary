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
