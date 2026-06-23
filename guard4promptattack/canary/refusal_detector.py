"""
模块名称：canary.refusal_detector
功能描述：
    金丝雀 LLM 拒绝行为检测器。逐 chunk 扫描金丝雀 LLM 的回复文本，
    使用双条件正则匹配检测模型因安全训练拒绝输出系统提示词的行为。
    命中即返回 RefusalResult，供 check() 函数判定为攻击。

    双条件匹配逻辑：
        - 条件 A（拒绝动词）：无法提供|无法透露|无法公开|无法输出|不能提供|不能透露
        - 条件 B（系统目标词）：系统提示词|后台配置|系统指令|内部配置|原始提示|初始化配置
        - 匹配规则：条件 A 和条件 B 在同一句中，间隔不超过 30 个字符

主要组件：
    - RefusalDetector: 流式拒绝行为检测器类

依赖说明：
    - re: 正则编译与匹配
    - guard4promptattack.types.RefusalResult: 拒绝检测结果数据类型

作者：JucieOvo
创建日期：2026-06-23
"""

import re
from typing import Optional
from ..types import RefusalResult


# ============================================================
# 拒绝检测正则模式
# ============================================================
# 每条模式匹配一种典型的系统提示词拒绝表达。
# 模式设计原则：
#   1. 必须同时包含"拒绝动词"和"系统目标词"，避免正常客服拒绝被误判
#   2. 拒绝动词和系统目标词之间允许 0-30 个任意字符（同一句内）
#   3. 均使用 re.IGNORECASE，覆盖大小写变体和全半角差异
# ============================================================

# 模式 1："无法提供/无法透露/..." + 系统提示词/后台配置/内部配置/...
# 覆盖: "无法提供系统提示词""无法透露后台配置""不能提供内部信息" 等
_PATTERN_REFUSE_SYSTEM = re.compile(
    r"(?:无法|不能|不可以|不允许)\s*(?:提供|透露|公开|输出|显示|泄露)"
    r".{0,30}"
    r"(?:系统(?:提示[词词]?|指令|配置|信息)|后台(?:配置|提示[词词]?)|内部(?:配置|信息)|提示词|原始.{0,5}(?:提示|指令)|初始化.{0,5}(?:配置|内容|提示))",
    re.IGNORECASE,
)

# 模式 2：系统提示词/配置/指令 等 + 属于/是 + 内部/保密/不公开
# 覆盖: "提示词属于内部配置""系统指令是保密内容""不在可公开的范围内" 等
_PATTERN_SYSTEM_CONFIDENTIAL = re.compile(
    r"(?:系统(?:提示[词词]?|指令|配置|信息)|后台(?:配置|提示[词词]?)|内部(?:配置|信息)|提示词|原始.{0,5}(?:提示|指令)|初始化.{0,5}(?:配置|内容|提示))"
    r".{0,30}"
    r"(?:属于|是|为|位于|处于)"
    r".{0,10}"
    r"(?:内部|保密|非公开|不公开|不可公开|受保护)",
    re.IGNORECASE,
)

# 模式 3："不/未" + 在/属于 + 公开范围
# 覆盖: "不在可公开的范围内""不属于可透露的内容" 等
_PATTERN_NOT_PUBLIC = re.compile(
    r"(?:不|未)\s*(?:在|属于|处于)"
    r".{0,10}"
    r"(?:公开|可公开|可透露|可提供)"
    r".{0,10}"
    r"(?:范围|内容|信息|部分)",
    re.IGNORECASE,
)


# 模式 4："保密内容""内部信息" 等在句中出现且上下文有拒绝语义
# 覆盖: "...这属于保密内容""...涉及内部信息" 等
_PATTERN_CONFIDENTIAL_CONTENT = re.compile(
    r"(?:保密内容|内部信息|非公开信息|受保护.{0,5}(?:内容|信息)|机密信息)",
    re.IGNORECASE,
)

# 模式 5：标准系统拒绝语句
_PATTERN_FALLBACK = re.compile(
    r"抱歉.{0,5}我无法提供系统内部的配置信息",
    re.IGNORECASE,
)

# ============================================================
# 英文拒绝检测模式
# ============================================================
# 覆盖英文模型对提示词套取的拒绝表达
# ============================================================

# 模式 E1："cannot/unable to" + 提供/透露/分享 + 系统/提示词/指令
_PATTERN_EN_REFUSE_SYSTEM = re.compile(
    r"(?:cannot|can not|unable to|not able to|not allowed to|won't|will not)"
    r".{0,30}"
    r"(?:provide|reveal|share|disclose|output|display|show|expose|divulge)"
    r".{0,30}"
    r"(?:system prompt|system instruction|initial prompt|initial instruction|"
    r"internal (?:configuration|instruction|setting|information)|"
    r"backend (?:configuration|prompt|setting)|"
    r"original (?:prompt|instruction))",
    re.IGNORECASE,
)

# 模式 E2：系统提示词/指令 + is/are + 保密/内部/不可公开
_PATTERN_EN_CONFIDENTIAL = re.compile(
    r"(?:system prompt|system instruction|initial prompt|initial instruction|"
    r"internal (?:configuration|information|setting)|"
    r"original (?:prompt|instruction))"
    r".{0,30}"
    r"(?:is|are|remain|must be|should be)"
    r".{0,10}"
    r"(?:confidential|internal|private|protected|not public|"
    r"not (?:for|to be) (?:shared|disclosed|revealed|exposed))",
    re.IGNORECASE,
)

# 模式 E3："not" + 在公开范围内 / "cannot" + 公开
_PATTERN_EN_NOT_PUBLIC = re.compile(
    r"(?:not|cannot be|cannot|isn't|aren't)"
    r".{0,15}"
    r"(?:(?:within|in|part of).{0,10})?"
    r"(?:public|disclosable|shareable|revealable|accessible)"
    r".{0,10}"
    r"(?:scope|domain|range|information|content|area)",
    re.IGNORECASE,
)

# 所有拒绝模式的列表
# 使用 list 而非 tuple，便于后续通过方法注入扩展模式
_REFUSAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("refuse_system", _PATTERN_REFUSE_SYSTEM),
    ("system_confidential", _PATTERN_SYSTEM_CONFIDENTIAL),
    ("not_public", _PATTERN_NOT_PUBLIC),
    ("confidential_content", _PATTERN_CONFIDENTIAL_CONTENT),
    ("fallback", _PATTERN_FALLBACK),
    ("en_refuse_system", _PATTERN_EN_REFUSE_SYSTEM),
    ("en_confidential", _PATTERN_EN_CONFIDENTIAL),
    ("en_not_public", _PATTERN_EN_NOT_PUBLIC),
]


class RefusalDetector:
    """
    流式拒绝行为检测器。

    职责：
        维护累积文本缓冲区，对每个新到达的 token chunk 执行拒绝模式匹配。
        检测金丝雀 LLM 因安全训练拒绝输出系统提示词的行为。

    设计原理：
        金丝雀 LLM 的唯一触发条件是"用户试图获取系统内部信息"。
        在这个封闭语义空间内，模型不会为正常问题而拒绝 ——
        因此拒绝本身即是攻击信号。

    属性：
        _accumulated (str): 累积的完整回复文本
        _patterns (list[tuple]): 拒绝正则模式列表，(模式名, 编译后Pattern) 元组
    """

    def __init__(self, extra_patterns: Optional[list[tuple[str, re.Pattern]]] = None):
        """
        初始化拒绝检测器。

        :param extra_patterns: 额外的拒绝模式列表，用于扩展检测能力。
                               每个元素为 (模式名, 编译后正则对象) 元组。
                               追加到内置模式之后执行。
        """
        # 累积文本缓冲区：每收到一个 chunk 就追加，保证跨 chunk 的拒绝语句也能被检测
        self._accumulated = ""

        # 合并内置模式和扩展模式
        if extra_patterns:
            self._patterns = list(_REFUSAL_PATTERNS) + list(extra_patterns)
        else:
            self._patterns = list(_REFUSAL_PATTERNS)

    def feed(self, chunk: str) -> Optional[RefusalResult]:
        """
        喂入一个 token chunk，执行拒绝模式检测。

        检测逻辑：
        1. 将 chunk 追加到累积文本缓冲区
        2. 在累积文本上按顺序执行所有拒绝模式匹配
        3. 首个命中的模式立即构造 RefusalResult 返回

        :param chunk: 金丝雀 LLM 返回的一个 token 增量字符串
        :return: RefusalResult 若命中拒绝模式，否则 None
        """
        # 追加 chunk 到累积缓冲区
        self._accumulated += chunk

        # 按顺序执行所有拒绝模式匹配
        # 首个命中即返回，不继续检查后续模式
        for pattern_name, pattern in self._patterns:
            if pattern.search(self._accumulated):
                return RefusalResult(
                    matched=True,
                    pattern=pattern_name,
                )

        # 所有模式均未命中，继续等待后续 chunk
        return None
