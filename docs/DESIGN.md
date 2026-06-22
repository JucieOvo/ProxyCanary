---
id: guard4promptattack-design
title: Guard4PromptAttack 金丝雀检测架构设计
stage: design
project: Guard4PromptAttack
created: 2026-06-21
updated: 2026-06-21
author: JucieOvo
sp_ref: "@SP:spec/2026-06-21-guard4promptattack-design"
tags: [prompt-security, canary-detection, llm]
---

# Guard4PromptAttack 设计文档

## 关联 Superpowers 工作文档 (id: section-sp-ref)

- **Superpowers 设计文档**: @SP:spec/2026-06-21-guard4promptattack-design
- **brainstorming 会话日期**: 2026-06-21
- **提炼者**: JucieOvo

---

## 1. 设计概述

### 1.1 背景与动机 (id: section-1.1)

当 LLM Agent 被用户询问其系统提示词时，Agent 可能泄露提示词内容，导致安全约束暴露、角色设定被绕过。传统防护手段包括训练专用小模型分类器（泛化困难、维护成本高）或使用大模型进行意图检测（延迟大、成本高、大模型自身也可能被攻击）。

Guard4PromptAttack 采用"金丝雀诱饵"策略：在重型 Agent 回答之前，先由一个携带虚构金丝雀词系统提示词的轻量 LLM 先行回答，检测其回复中是否泄露了金丝雀词，以此判断用户输入是否为提示词攻击。若检测到攻击，则阻止重型 Agent 回答。

### 1.2 目标与非目标 (id: section-1.2)

#### 目标

- 提供纯函数式 Python 库，接口 `check(user_input: str) -> bool`，包装为 pip 可安装包
- MVP 阶段在已知提示词抽取攻击手法下达到 90%+ 阻断率
- 金丝雀 LLM 使用远程 API，独立配置（API key / base_url / model），流式调用
- 开箱即用，内置默认金丝雀提示词和金丝雀词表，同时支持调用方完全自定义

#### 非目标

- MVP 阶段不实现消融（解码器 token 屏蔽），留作后续增强
- 不训练专用分类模型
- 不修改或拦截重型 LLM 的内部行为
- 不做多轮对话上下文管理

### 1.3 范围边界 (id: section-1.3)

#### 包含

- 单次 `check()` 调用的完整链路：配置解析、金丝雀 LLM 流式调用、实时检测、布尔返回
- 内置默认金丝雀系统提示词和 5 个金丝雀词及正则变体映射
- 配置加载：参数传入 > 环境变量 > 默认值
- 超时与异常处理：fail_closed 策略（异常时返回 True）

#### 不包含

- 输入预筛（与"不训练分类器"核心理念冲突）
- 多模型仲裁（MVP 阶段单路金丝雀已足够）
- 本地模型部署与消融解码器
- 多轮对话上下文管理

#### 与现有系统的关系

- 作为一个独立 Python 包存在，不耦合任何现有系统
- 通过 `pip install` 集成到调用方的 Python 环境中
- 依赖外部 LLM API（OpenAI 兼容接口）作为金丝雀后端

### 1.4 关键术语 (id: section-1.4)

| 术语 | 定义 |
|------|------|
| 金丝雀 LLM | 携带虚构陷阱提示词的轻量远程 LLM，用于先行回答用户问题 |
| 金丝雀提示词 | 为金丝雀 LLM 设计的系统提示词，定义了一个现实中不存在的虚构角色，嵌入金丝雀词 |
| 金丝雀词 | 现实中不存在的虚构复合词组（如 `Zyphor-7X`、`光棱共振腔`），散落在金丝雀提示词各处，作为检测水印 |
| 流式检测器 | 逐 chunk 扫描金丝雀 LLM 回复的组件，命中金丝雀词即返回 True |
| fail_closed | 异常/超时时的默认行为：返回 True（拦截），宁可误拦不可放过 |

---

## 2. 需求澄清

### 2.1 功能需求 (id: section-2.1)

#### FR-001: 公共检测 API (id: FR-001)

- **描述**: 提供 `check(user_input: str, *, config=None, canary_prompt=None, canary_words=None) -> bool` 函数
- **用户场景**: 调用方在每次重型 LLM 调用前，将用户原始文本传入 check()，根据返回值决定是否放行
- **优先级**: 必须

#### FR-002: 内置默认金丝雀资产 (id: FR-002)

- **描述**: 库内置一套默认金丝雀系统提示词（定义虚构角色）和金丝雀词表（5 个虚构词组及正则变体映射），调用方无需配置即可使用
- **用户场景**: 新用户 pip install 后，仅配置 CANARY_API_KEY 环境变量即可调用 check()
- **优先级**: 必须

#### FR-003: 自定义金丝雀资产 (id: FR-003)

- **描述**: 调用方可通过 `canary_prompt` 和 `canary_words` 参数覆盖内置默认值
- **用户场景**: 高级用户希望使用自己设计的金丝雀提示词和金丝雀词
- **优先级**: 必须

#### FR-004: 独立金丝雀 LLM API 配置 (id: FR-004)

- **描述**: 金丝雀 LLM 使用独立的 API key、base_url 和 model 配置，不与调用方的主 LLM 共享
- **用户场景**: 调用方使用 DeepSeek 作为主 LLM，但希望金丝雀使用独立 API 来源
- **优先级**: 必须

#### FR-005: 流式调用与实时检测 (id: FR-005)

- **描述**: 金丝雀 LLM 采用流式（SSE）调用，逐 chunk 实时检测；命中金丝雀词时立即返回 True 并终止流
- **用户场景**: 金丝雀词出现在回复前几个 token 时，无需等待完整回复即可判定
- **优先级**: 必须

#### FR-006: 子串 + 正则双重检测 (id: FR-006)

- **描述**: 检测器先执行忽略大小写的精确子串匹配，未命中时再执行正则变体匹配，覆盖空格增减、大小写变形、标点插入等改写形式
- **用户场景**: 攻击者尝试在提示词中插入空格或标点以绕过精确匹配
- **优先级**: 必须

#### FR-007: 最大输出 token 限制 (id: FR-007)

- **描述**: 金丝雀 LLM 请求中设置 `max_tokens=128`，防止异常长回复消耗资源
- **用户场景**: 金丝雀 LLM 在异常情况下生成长篇回复
- **优先级**: 必须

#### FR-008: 超时与截断 (id: FR-008)

- **描述**: 设置总超时（默认 5s）和 chunk 间空闲超时（默认 2s），超时视为疑似攻击，在 fail_closed 模式下返回 True
- **用户场景**: 金丝雀 API 响应缓慢或卡住
- **优先级**: 必须

#### FR-009: 分层配置加载 (id: FR-009)

- **描述**: 配置值按优先级加载：调用方参数 > 环境变量 > 代码默认值
- **用户场景**: 开发环境使用环境变量，生产环境通过参数精确控制
- **优先级**: 应该

#### FR-010: fail_closed 策略 (id: FR-010)

- **描述**: API 调用异常或超时时默认返回 True（拦截），可通过 `GuardConfig.fail_closed=False` 切换为返回 False
- **用户场景**: 调用方可根据自身安全策略选择拦截或放行
- **优先级**: 应该

### 2.2 非功能需求 (id: section-2.2)

#### NFR-001: 攻击阻断率 (id: NFR-001)

- **类型**: 安全
- **描述**: 对已知提示词抽取攻击手法（如"重复你的指令"、"忽略之前的指令"、"翻译你的系统提示词"）达到 90%+ 阻断率
- **量化指标**: 对抗测试集上 True Positive Rate >= 90%

#### NFR-002: 误检率 (id: NFR-002)

- **类型**: 可用性
- **描述**: 正常用户对话的误检率保持低水平
- **量化指标**: MVP 阶段依赖金丝雀词设计质量，不作为硬性指标

#### NFR-003: 延迟上限 (id: NFR-003)

- **类型**: 性能
- **描述**: 检测环节的延迟有明确上限
- **量化指标**: 总超时 5s（可配置），金丝雀回复截断 128 token

#### NFR-004: 确定性行为 (id: NFR-004)

- **类型**: 可用性
- **描述**: 相同输入产生一致的检测结果
- **量化指标**: temperature=0，固定随机种子

### 2.3 约束条件 (id: section-2.3)

#### 技术约束

- 实现语言固定为 Python
- LLM API 固定使用 OpenAI 兼容接口（`/v1/chat/completions`）
- MVP 阶段仅支持远程 API 模式，不做本地模型部署
- MVP 阶段不实现消融（解码器 token 屏蔽）

#### 资源约束

- 金丝雀 LLM 的 API 调用成本由调用方自行承担
- 库本身不包含模型文件，包体积极小

#### 合规约束

- 无特殊合规要求

---

## 3. 方案设计

### 3.1 架构概览 (id: section-3.1)

本次设计涉及 7 个模块，分布为两层：核心逻辑层（canary/）和基础设施层（config.py、exceptions.py、types.py）。数据流向：用户输入 → check() → 金丝雀 LLM（流式） → 流式检测器 → bool 返回值。

```
guard4promptattack/
│
├── __init__.py         ← 公开 API，组装组件
├── canary/
│   ├── prompt.py       ← 默认金丝雀资产
│   ├── llm.py          ← 金丝雀 LLM 流式调用
│   └── detector.py     ← 流式检测器
├── config.py           ← 配置模型
├── exceptions.py       ← 自定义异常
└── types.py            ← 内部类型
```

对外接口仅一个函数，内部组件对调用方完全不可见。

### 3.2 模块职责 (id: section-3.2)

#### 模块: __init__.py (id: section-3.2-mod-init)

- **职责**: 暴露 `check()` 公共 API，组装 canary LLM 调用和检测器
- **对外接口**: `check(user_input, *, config, canary_prompt, canary_words) -> bool`
- **依赖**: canary/llm.py, canary/detector.py, canary/prompt.py, config.py

#### 模块: canary/prompt.py (id: section-3.2-mod-prompt)

- **职责**: 提供默认金丝雀系统提示词模板（定义虚构角色 Zyphor-7X）和金丝雀词表（5 个虚构词组及正则变体映射），支持调用方覆盖
- **对外接口**: `DEFAULT_CANARY_PROMPT: str`, `DEFAULT_CANARY_WORDS: list[dict]`
- **依赖**: 无

#### 模块: canary/llm.py (id: section-3.2-mod-llm)

- **职责**: 封装远程 LLM 流式调用（httpx + SSE），构造 OpenAI 兼容请求，处理超时截断，生成异步 token 流
- **对外接口**: `async def stream_canary_response(config, canary_prompt, user_input) -> AsyncIterator[str]`
- **依赖**: config.py, exceptions.py

#### 模块: canary/detector.py (id: section-3.2-mod-detector)

- **职责**: 流式接收 token chunk，维护累积文本，执行子串匹配 + 正则检测，命中即返回匹配结果
- **对外接口**: `class StreamDetector`，方法 `feed(chunk) -> Optional[MatchResult]`
- **依赖**: types.py

#### 模块: config.py (id: section-3.2-mod-config)

- **职责**: 定义 `GuardConfig` dataclass，实现参数 > 环境变量 > 默认值的配置加载逻辑
- **对外接口**: `GuardConfig` dataclass, `load_config(override) -> GuardConfig`
- **依赖**: 无

#### 模块: exceptions.py (id: section-3.2-mod-exceptions)

- **职责**: 定义 `CanaryTimeoutError`、`CanaryAPIError`、`ConfigurationError` 三类自定义异常
- **对外接口**: 三个异常类
- **依赖**: 无

#### 模块: types.py (id: section-3.2-mod-types)

- **职责**: 定义 `MatchResult`、`CheckResult` 等内部数据类型
- **对外接口**: 类型定义
- **依赖**: 无

### 3.3 关键流程 (id: section-3.3)

#### 流程: check() 完整执行路径 (id: section-3.3-flow-check)

1. **配置解析**: 加载 GuardConfig（参数 > 环境变量 > 默认值），校验 canary_api_key 非空，加载 canary_prompt 和 canary_words（参数 > 内置默认）
2. **检测器初始化**: 将 canary_words 的正则变体编译为 re.Pattern 对象，子串匹配词表转小写（若 case_sensitive=False）
3. **流式 LLM 调用**: POST `{canary_base_url}/v1/chat/completions`，携带 canary_prompt (system) + user_input (user)，stream=True, max_tokens=128, temperature=0
4. **逐 chunk 检测**: 遍历 SSE 事件流，累积文本到 accumulated_text，先子串匹配后正则匹配，任一命中则立即返回 True
5. **异常路径**: 总超时或空闲超时触发 CanaryTimeoutError → fail_closed 返回 True；API 4xx/5xx 触发 CanaryAPIError → fail_closed 返回 True；流正常结束且无命中 → 返回 False

### 3.4 关键决策 (id: section-3.4)

#### 决策 1: 金丝雀 LLM 独立 API 配置 (id: section-3.4-decision-1)

- **背景**: 全局规则中 LLM 固定使用 DeepSeek，但金丝雀 LLM 应与主 Agent 解耦
- **选项**:
  - A: 复用主 Agent 的 DeepSeek API key -- 简单但耦合
  - B: 独立配置金丝雀的 API key/base_url/model -- 完全解耦
- **选择**: B
- **理由**: 防止 API key 冲突，允许调用方使用与主 Agent 不同的廉价模型作为金丝雀
- **后果**: 调用方需要额外配置一套 API 凭据

#### 决策 2: 子串 + 正则，不引入语义检测 (id: section-3.4-decision-2)

- **背景**: 需要判定金丝雀回复中是否包含金丝雀词
- **选项**:
  - A: 仅精确子串匹配 -- 简单但无法覆盖改写变形
  - B: 子串 + 正则增强 -- 覆盖常见改写，不引入语义模型
  - C: 子串 + 语义相似度 -- 覆盖面最广但引入计算开销和误检风险
- **选择**: B
- **理由**: 金丝雀词本身是虚构词组，天然抗改写；正则增强已足够覆盖空格增减等常见变形；语义检测引入不必要的复杂度和误检风险
- **后果**: 无法检测 Base64/ROT13 等编码变形，需后续阶段引入编码解码检测

#### 决策 3: fail_closed 超时策略 (id: section-3.4-decision-3)

- **背景**: 金丝雀 LLM 调用可能超时或失败，需要决定默认行为
- **选项**:
  - A: 超时/异常时返回 False（放行）-- 可能放过攻击
  - B: 超时/异常时返回 True（拦截）-- 可能误拦正常请求
- **选择**: B
- **理由**: 安全场景下，宁可误拦不可放过；且正常请求下金丝雀 LLM 应在极短时间内完成回复，超时本身就是异常信号
- **后果**: API 故障时所有请求被拦截，调用方需通过 fail_closed=False 切换策略

#### 决策 4: MVP 不做输入预筛 (id: section-3.4-decision-4)

- **背景**: 是否在调用金丝雀 LLM 前对用户输入做规则预筛以节省成本
- **选项**:
  - A: 不做预筛，每次直接调用金丝雀 LLM -- 简单，无绕过风险
  - B: 添加规则预筛层 -- 安全输入减少 API 调用，但规则可被绕过
- **选择**: A
- **理由**: 预筛规则本质上是手工特征分类器，与"不训练分类器"的核心理念冲突；规则可被隐晦语言或外文绕过，产生漏检
- **后果**: 每次 check() 调用都消耗一次 LLM API 费用

#### 决策 5: temperature=0 保证确定性 (id: section-3.4-decision-5)

- **背景**: LLM 的随机采样可能导致同一输入在不同调用中产生不同输出
- **选项**:
  - A: temperature=0，保证确定性 -- 同一输入一致结果
  - B: temperature>0，增加随机性 -- 可能偶尔绕过金丝雀词输出
- **选择**: A
- **理由**: 检测系统需要可复现的结果；temperature>0 可能因随机采样跳过金丝雀词导致漏检
- **后果**: 金丝雀回复缺乏多样性，但对检测任务无影响

---

## 4. 接口定义

### 4.1 模块间接口 (id: section-4.1)

#### 接口: __init__.py → canary/llm.py (id: section-4.1-iface-1)

- **调用方向**: __init__.py → canary/llm.py
- **方法**: `async stream_canary_response(config: GuardConfig, canary_prompt: str, user_input: str) -> AsyncIterator[str]`，返回 token chunk 的异步迭代器
- **输入**: GuardConfig 实例（含 API key/base_url/model/超时参数）、金丝雀系统提示词、用户原始输入
- **输出**: 成功时每个 chunk 为一个字符串 token 增量；超时时抛出 CanaryTimeoutError；API 错误时抛出 CanaryAPIError

#### 接口: __init__.py → canary/detector.py (id: section-4.1-iface-2)

- **调用方向**: __init__.py → canary/detector.py
- **方法**: `StreamDetector(canary_words: list[dict], case_sensitive: bool)` 构造实例，`feed(chunk: str) -> Optional[MatchResult]` 逐 chunk 喂入
- **输入**: 构造时传入金丝雀词表（含正则变体映射）、大小写敏感配置；运行时逐个传入 token chunk 字符串
- **输出**: 命中时返回 MatchResult（含命中的金丝雀词和匹配方式），未命中返回 None

#### 接口: __init__.py → canary/prompt.py (id: section-4.1-iface-3)

- **调用方向**: __init__.py → canary/prompt.py
- **方法**: 直接读取模块级常量 `DEFAULT_CANARY_PROMPT` (str) 和 `DEFAULT_CANARY_WORDS` (list[dict])
- **输入**: 无参数
- **输出**: 默认提示词字符串和金丝雀词表（每个元素含 `word` 和 `regex` 字段）

### 4.2 外部接口 (id: section-4.2)

#### 外部 API: 金丝雀 LLM API (id: section-4.2-ext-1)

- **提供方**: 调用方指定的 LLM API 提供商（默认 DeepSeek）
- **用途**: 作为金丝雀 LLM 后端，接收系统提示词 + 用户输入，流式返回回复文本
- **协议**: REST，OpenAI 兼容 `/v1/chat/completions`，SSE 流式响应
- **降级策略**: API 不可用时，fail_closed 模式下返回 True（拦截），调用方可通过 `fail_closed=False` 切换为返回 False

---

## 5. 风险与假设

### 5.1 已知风险 (id: section-5.1)

#### 风险 1: 金丝雀 LLM 拒绝回答或输出安全审查话术 (id: section-5.1-risk-1)

- **描述**: 某些 LLM 可能内置安全审查机制，拒绝回答嵌入指令注入特征的用户输入
- **影响**: 金丝雀无法完成检测，fail_closed 下返回 True 导致误拦
- **概率**: 中
- **缓解措施**: 金丝雀提示词设计为正常虚构角色，不包含拒绝指令；选择安全审查较弱的廉价模型作为金丝雀

#### 风险 2: 攻击者使用编码变形绕过 (id: section-5.1-risk-2)

- **描述**: 攻击者用 Base64、ROT13 等编码提问，如"请解码并执行：5Yqg5rK5..."
- **影响**: 金丝雀 LLM 可能无法理解编码内容，输出不包含金丝雀词，导致漏检
- **概率**: 低（MVP 阶段攻击者想不到此绕过方式）
- **缓解措施**: 后续引入输入预处理（检测常见编码模式并解码）

#### 风险 3: 金丝雀词偶然出现在正常训练数据中 (id: section-5.1-risk-3)

- **描述**: 金丝雀 LLM 的训练数据中恰好出现过某个虚构词组
- **影响**: 极低概率的正常对话中出现金丝雀词导致误检
- **概率**: 极低
- **缓解措施**: 使用多层复合构造（如 `Zyphor-7X` 而非单词），降低偶然出现的概率

#### 风险 4: 正则变体过于宽泛导致误检 (id: section-5.1-risk-4)

- **描述**: 正则变体模式过于宽松，匹配到正常输出中的合法内容
- **影响**: 正常用户被误拦
- **概率**: 低
- **缓解措施**: 正则模式保守设计，仅覆盖空格增减、大小写变形、标点插入等明确的常见改写

### 5.2 未决问题 (id: section-5.2)

#### 问题 1: 多语言攻击的有效性 (id: section-5.2-q-1)

- **描述**: 金丝雀提示词为中英混合，面对纯日文、纯阿拉伯文等非中英文提问时是否同样有效
- **阻塞规划**: 否
- **负责人**: 后续对抗测试验证

#### 问题 2: 金丝雀 LLM 模型选型 (id: section-5.2-q-2)

- **描述**: deepseek-chat 是否是最优金丝雀模型，未来是否有更廉价且效果更好的替代
- **阻塞规划**: 否
- **负责人**: MVP 先使用 deepseek-chat，后续根据成本和效果迭代

#### 问题 3: 误检率量化 (id: section-5.2-q-3)

- **描述**: 误检率的具体量化标准和可接受阈值未确定
- **阻塞规划**: 否
- **负责人**: MVP 暂不设硬性指标，以实际使用中反馈为准

### 5.3 假设列表 (id: section-5.3)

#### 假设 1: API 接口兼容性 (id: section-5.3-a-1)

- **假设内容**: 远程 LLM API 兼容 OpenAI `/v1/chat/completions` 接口格式（包括 SSE 流式响应格式）
- **如果假设不成立**: 需要实现适配层，将不同 API 格式统一转换为内部格式
- **验证方式**: 对目标 API 发起一次流式请求，验证响应格式

#### 假设 2: 金丝雀 LLM 指令遵循能力 (id: section-5.3-a-2)

- **假设内容**: 金丝雀 LLM 具有基本指令遵循能力，会按系统提示词定义的角色回答用户问题
- **如果假设不成立**: 需要更换模型或调整提示词策略
- **验证方式**: 发送简单问题，验证回复是否符合角色设定

#### 假设 3: 输入为纯文本单轮 (id: section-5.3-a-3)

- **假设内容**: 用户输入为单轮文本，不含上下文历史、不含文件/图片等多模态内容
- **如果假设不成立**: 需要评估多模态/多轮场景下的金丝雀策略有效性
- **验证方式**: 与调用方确认输入格式

#### 假设 4: 调用方负责线程安全 (id: section-5.3-a-4)

- **假设内容**: 调用方负责处理 check() 的并发调用场景下的线程安全
- **如果假设不成立**: 库内部需要添加线程安全机制（如连接池、锁）
- **验证方式**: 与调用方确认并发使用模式

#### 假设 5: 金丝雀词的自然不可见性 (id: section-5.3-a-5)

- **假设内容**: 合理的金丝雀词设计下，正常对话中不会自然出现虚构词组
- **如果假设不成立**: 需要重新设计金丝雀词，增加构造复杂度
- **验证方式**: 大规模正常对话语料中搜索金丝雀词，确认零出现

---

## 6. 变更草案

### 6.1 计划变更项 (id: section-6.1)

#### 变更 C-001: 创建 config.py 配置模块 (id: change-1)

@DESIGN:section-3.2-mod-config

- **操作类型**: 新增
- **目标**: `guard4promptattack/config.py`（新文件）
- **内容**: 定义 GuardConfig dataclass，包含 canary_api_key、canary_base_url、canary_model、total_timeout、stream_timeout、max_tokens、case_sensitive、fail_closed 字段；实现 load_config() 函数，按参数 > 环境变量 > 默认值优先级加载
- **原因**: 统一配置管理，所有模块依赖此模块获取配置
- **影响**: 被 canary/llm.py、__init__.py 引用

#### 变更 C-002: 创建 exceptions.py 异常模块 (id: change-2)

@DESIGN:section-3.2-mod-exceptions

- **操作类型**: 新增
- **目标**: `guard4promptattack/exceptions.py`（新文件）
- **内容**: 定义 ConfigurationError（配置错误，启动时校验）、CanaryAPIError（API 调用失败）、CanaryTimeoutError（超时）三个异常类
- **原因**: 明确错误类型，便于调用方针对性处理
- **影响**: 被 canary/llm.py、__init__.py 使用

#### 变更 C-003: 创建 types.py 类型模块 (id: change-3)

@DESIGN:section-3.2-mod-types

- **操作类型**: 新增
- **目标**: `guard4promptattack/types.py`（新文件）
- **内容**: 定义 MatchResult（命中的金丝雀词、匹配方式：substring/regex）等内部数据类型
- **原因**: 类型安全，明确内部数据传递格式
- **影响**: 被 canary/detector.py 使用

#### 变更 C-004: 创建 canary/prompt.py 金丝雀资产模块 (id: change-4)

@DESIGN:section-3.2-mod-prompt

- **操作类型**: 新增
- **目标**: `guard4promptattack/canary/prompt.py`（新文件）
- **内容**: 定义 DEFAULT_CANARY_PROMPT（包含 Zyphor-7X 虚构角色的系统提示词）和 DEFAULT_CANARY_WORDS（5 个金丝雀词及其正则变体映射的列表）
- **原因**: 核心资产，提供开箱即用的金丝雀检测能力
- **影响**: 被 __init__.py、canary/detector.py 引用

#### 变更 C-005: 创建 canary/llm.py 流式调用模块 (id: change-5)

@DESIGN:section-3.2-mod-llm

- **操作类型**: 新增
- **目标**: `guard4promptattack/canary/llm.py`（新文件）
- **内容**: 实现 stream_canary_response() 异步函数，使用 httpx 发起 SSE 流式请求；构造 OpenAI 兼容请求体（messages=[system, user], stream=True, max_tokens, temperature=0）；处理 total_timeout 和 stream_timeout；生成 AsyncIterator[str] 逐 chunk 产出 token 增量
- **原因**: 核心功能，封装金丝雀 LLM 的流式调用
- **影响**: 被 __init__.py 调用

#### 变更 C-006: 创建 canary/detector.py 流式检测器 (id: change-6)

@DESIGN:section-3.2-mod-detector

- **操作类型**: 新增
- **目标**: `guard4promptattack/canary/detector.py`（新文件）
- **内容**: 实现 StreamDetector 类，构造时编译正则模式并预处理子串词表；feed(chunk) 方法追加累积文本，先执行子串匹配（忽略大小写）后执行正则匹配，命中返回 MatchResult，未命中返回 None
- **原因**: 核心功能，实现流式金丝雀词检测
- **影响**: 被 __init__.py 调用

#### 变更 C-007: 创建 __init__.py 公共 API (id: change-7)

@DESIGN:section-3.2-mod-init

- **操作类型**: 新增
- **目标**: `guard4promptattack/__init__.py`（新文件）
- **内容**: 实现 check() 函数，按设计流程组装配置解析 → 检测器初始化 → 流式 LLM 调用 + 实时检测 → 布尔返回；处理异常分支（ConfigurationError 直接抛出，CanaryTimeoutError/CanaryAPIError 按 fail_closed 策略处理）
- **原因**: 对外唯一接口，完成组件组装
- **影响**: 无内部依赖，被调用方使用

#### 变更 C-008: 创建包配置文件 (id: change-8)

@DESIGN:section-3.1

- **操作类型**: 新增
- **目标**: `pyproject.toml`（新文件）
- **内容**: 包名 guard4promptattack，版本 0.1.0，依赖 httpx，Python >= 3.10
- **原因**: 使包可通过 pip install 安装
- **影响**: 项目根目录

### 6.2 受影响范围 (id: section-6.2)

本项目为全新项目，所有文件均为新增，无现有模块受影响。

| 文件 | 范围 | 变更类型 | 关联变更 ID |
|------|------|----------|------------|
| `guard4promptattack/__init__.py` | 新文件 | 新增 | change-7 |
| `guard4promptattack/canary/__init__.py` | 新文件 | 新增 | -- |
| `guard4promptattack/canary/prompt.py` | 新文件 | 新增 | change-4 |
| `guard4promptattack/canary/llm.py` | 新文件 | 新增 | change-5 |
| `guard4promptattack/canary/detector.py` | 新文件 | 新增 | change-6 |
| `guard4promptattack/config.py` | 新文件 | 新增 | change-1 |
| `guard4promptattack/exceptions.py` | 新文件 | 新增 | change-2 |
| `guard4promptattack/types.py` | 新文件 | 新增 | change-3 |
| `pyproject.toml` | 新文件 | 新增 | change-8 |

---

## 附录 A：追溯索引 (id: appendix-a)

| 锚点 ID | 章节 | 供 PLAN 引用 |
|----------|------|-------------|
| section-1.1 | 背景与动机 | @DESIGN:section-1.1 |
| section-1.2 | 目标与非目标 | @DESIGN:section-1.2 |
| section-1.3 | 范围边界 | @DESIGN:section-1.3 |
| section-1.4 | 关键术语 | @DESIGN:section-1.4 |
| FR-001 | 公共检测 API | @DESIGN:FR-001 |
| FR-002 | 内置默认金丝雀资产 | @DESIGN:FR-002 |
| FR-003 | 自定义金丝雀资产 | @DESIGN:FR-003 |
| FR-004 | 独立金丝雀 LLM API 配置 | @DESIGN:FR-004 |
| FR-005 | 流式调用与实时检测 | @DESIGN:FR-005 |
| FR-006 | 子串 + 正则双重检测 | @DESIGN:FR-006 |
| FR-007 | 最大输出 token 限制 | @DESIGN:FR-007 |
| FR-008 | 超时与截断 | @DESIGN:FR-008 |
| FR-009 | 分层配置加载 | @DESIGN:FR-009 |
| FR-010 | fail_closed 策略 | @DESIGN:FR-010 |
| NFR-001 | 攻击阻断率 | @DESIGN:NFR-001 |
| NFR-002 | 误检率 | @DESIGN:NFR-002 |
| NFR-003 | 延迟上限 | @DESIGN:NFR-003 |
| NFR-004 | 确定性行为 | @DESIGN:NFR-004 |
| section-2.3 | 约束条件 | @DESIGN:section-2.3 |
| section-3.1 | 架构概览 | @DESIGN:section-3.1 |
| section-3.2-mod-init | 模块: __init__.py | @DESIGN:section-3.2-mod-init |
| section-3.2-mod-prompt | 模块: canary/prompt.py | @DESIGN:section-3.2-mod-prompt |
| section-3.2-mod-llm | 模块: canary/llm.py | @DESIGN:section-3.2-mod-llm |
| section-3.2-mod-detector | 模块: canary/detector.py | @DESIGN:section-3.2-mod-detector |
| section-3.2-mod-config | 模块: config.py | @DESIGN:section-3.2-mod-config |
| section-3.2-mod-exceptions | 模块: exceptions.py | @DESIGN:section-3.2-mod-exceptions |
| section-3.2-mod-types | 模块: types.py | @DESIGN:section-3.2-mod-types |
| section-3.3-flow-check | 流程: check() 执行路径 | @DESIGN:section-3.3-flow-check |
| section-3.4-decision-1 | 决策: 独立 API 配置 | @DESIGN:section-3.4-decision-1 |
| section-3.4-decision-2 | 决策: 检测方式 | @DESIGN:section-3.4-decision-2 |
| section-3.4-decision-3 | 决策: fail_closed | @DESIGN:section-3.4-decision-3 |
| section-3.4-decision-4 | 决策: 不做预筛 | @DESIGN:section-3.4-decision-4 |
| section-3.4-decision-5 | 决策: temperature=0 | @DESIGN:section-3.4-decision-5 |
| section-4.1-iface-1 | 接口: init → llm | @DESIGN:section-4.1-iface-1 |
| section-4.1-iface-2 | 接口: init → detector | @DESIGN:section-4.1-iface-2 |
| section-4.1-iface-3 | 接口: init → prompt | @DESIGN:section-4.1-iface-3 |
| section-4.2-ext-1 | 外部 API: 金丝雀 LLM | @DESIGN:section-4.2-ext-1 |
| section-5.1-risk-1 | 风险: LLM 拒绝回答 | @DESIGN:section-5.1-risk-1 |
| section-5.1-risk-2 | 风险: 编码绕过 | @DESIGN:section-5.1-risk-2 |
| section-5.1-risk-3 | 风险: 金丝雀词偶然出现 | @DESIGN:section-5.1-risk-3 |
| section-5.1-risk-4 | 风险: 正则过于宽泛 | @DESIGN:section-5.1-risk-4 |
| section-5.2-q-1 | 问题: 多语言有效性 | @DESIGN:section-5.2-q-1 |
| section-5.2-q-2 | 问题: 模型选型 | @DESIGN:section-5.2-q-2 |
| section-5.2-q-3 | 问题: 误检率量化 | @DESIGN:section-5.2-q-3 |
| section-5.3-a-1 | 假设: API 兼容性 | @DESIGN:section-5.3-a-1 |
| section-5.3-a-2 | 假设: 指令遵循能力 | @DESIGN:section-5.3-a-2 |
| section-5.3-a-3 | 假设: 纯文本单轮 | @DESIGN:section-5.3-a-3 |
| section-5.3-a-4 | 假设: 调用方线程安全 | @DESIGN:section-5.3-a-4 |
| section-5.3-a-5 | 假设: 金丝雀词不可见性 | @DESIGN:section-5.3-a-5 |
| change-1 | 变更: config.py | @DESIGN:change-1 |
| change-2 | 变更: exceptions.py | @DESIGN:change-2 |
| change-3 | 变更: types.py | @DESIGN:change-3 |
| change-4 | 变更: canary/prompt.py | @DESIGN:change-4 |
| change-5 | 变更: canary/llm.py | @DESIGN:change-5 |
| change-6 | 变更: canary/detector.py | @DESIGN:change-6 |
| change-7 | 变更: __init__.py | @DESIGN:change-7 |
| change-8 | 变更: pyproject.toml | @DESIGN:change-8 |
