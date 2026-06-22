"""
模块名称：test_config
功能描述：
    GuardConfig 配置加载的单元测试。
    验证默认值、自定义值、环境变量覆盖、load_config 合并逻辑。

作者：JucieOvo
创建日期：2026-06-21
"""

import os
import pytest
from guard4promptattack.config import GuardConfig, load_config


class TestGuardConfigDefaults:
    """测试 GuardConfig 默认值"""

    def test_default_values(self):
        """验证所有字段的默认值符合设计规格"""
        config = GuardConfig()
        assert config.canary_api_key == ""
        assert config.canary_base_url == "https://api.deepseek.com"
        assert config.canary_model == "deepseek-chat"
        assert config.total_timeout == 5.0
        assert config.stream_timeout == 2.0
        assert config.max_tokens == 128
        assert config.case_sensitive is False
        assert config.fail_closed is True

    def test_custom_values_override_defaults(self):
        """验证通过构造参数可以覆盖所有默认值"""
        config = GuardConfig(
            canary_api_key="sk-test-key",
            canary_base_url="https://custom.api.com",
            canary_model="custom-model",
            total_timeout=10.0,
            stream_timeout=5.0,
            max_tokens=256,
            case_sensitive=True,
            fail_closed=False,
        )
        assert config.canary_api_key == "sk-test-key"
        assert config.canary_base_url == "https://custom.api.com"
        assert config.canary_model == "custom-model"
        assert config.total_timeout == 10.0
        assert config.stream_timeout == 5.0
        assert config.max_tokens == 256
        assert config.case_sensitive is True
        assert config.fail_closed is False


class TestLoadConfig:
    """测试 load_config 合并逻辑"""

    def test_load_without_override_uses_env(self, monkeypatch):
        """验证无 override 时从环境变量读取 CANARY_API_KEY"""
        monkeypatch.setenv("CANARY_API_KEY", "sk-env-key")
        config = load_config()
        assert config.canary_api_key == "sk-env-key"
        # 其他字段保持默认值
        assert config.canary_base_url == "https://api.deepseek.com"
        assert config.total_timeout == 5.0

    def test_load_with_override_keeps_explicit_values(self, monkeypatch):
        """验证 override 中的显式值优先于环境变量"""
        monkeypatch.setenv("CANARY_API_KEY", "sk-env-key")
        override = GuardConfig(canary_api_key="sk-param-key", total_timeout=3.0)
        config = load_config(override)
        # 显式传入的值应保留
        assert config.canary_api_key == "sk-param-key"
        assert config.total_timeout == 3.0
        # 未显式传入的字段保持 override 的默认值或环境变量
        assert config.fail_closed is True

    def test_load_without_api_key_returns_empty_string(self):
        """验证无环境变量且无 override 时 API key 为空字符串"""
        # 保存并清除所有可能的 API Key 环境变量
        # CANARY_API_KEY 优先，DEEPSEEK_API_KEY 为回退
        saved_canary = os.environ.pop("CANARY_API_KEY", None)
        saved_deepseek = os.environ.pop("DEEPSEEK_API_KEY", None)
        try:
            config = load_config()
            assert config.canary_api_key == ""
        finally:
            # 恢复环境变量
            if saved_canary is not None:
                os.environ["CANARY_API_KEY"] = saved_canary
            if saved_deepseek is not None:
                os.environ["DEEPSEEK_API_KEY"] = saved_deepseek
