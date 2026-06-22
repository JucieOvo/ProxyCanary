---
id: guard4promptattack-plan
title: Guard4PromptAttack MVP 实现规划
stage: plan
project: Guard4PromptAttack
created: 2026-06-21
updated: 2026-06-21
author: JucieOvo
sp_ref: "@SP:plan/2026-06-21-guard4promptattack-mvp"
tags: [prompt-security, canary-detection, mvp-plan]
---

# Guard4PromptAttack MVP 实现规划

## 关联 Superpowers 工作文档 (id: section-sp-ref)

- **Superpowers 计划文档**: @SP:plan/2026-06-21-guard4promptattack-mvp
- **writing-plans 会话日期**: 2026-06-21
- **提炼者**: JucieOvo
- **说明**: 本文档是 Superpowers 计划的人类可读摘要。任务执行细节（代码、命令、TDD 步骤）见原文档。

---

## 1. 规划概述

### 1.1 规划目标 (id: section-1.1)

将 @DESIGN:section-1.2 中定义的 4 个目标拆解为 7 个任务，遵循 TDD（测试先行）方法论。

#### 阶段划分

- **阶段 1：基础搭建** -- T-001~T-003，3 个任务，目标：包骨架就位、配置体系建立、金丝雀资产可用
- **阶段 2：核心逻辑** -- T-004~T-005，2 个任务，目标：流式检测器和 LLM 客户端完成，可独立检验
- **阶段 3：组装与验证** -- T-006~T-007，2 个任务，目标：check() 公开 API 贯通，端到端攻击阻断率验证

### 1.2 任务依赖总览 (id: section-1.2)

```
T-001 (骨架)
  │
  ├── T-002 (基础设施)
  │     ├── T-004 (检测器)
  │     └── T-005 (LLM客户端)
  │
  └── T-003 (金丝雀资产)
        │
        └── T-006 (check API) ──→ T-007 (端到端验证)
              (需要 T-003 + T-004 + T-005)
```

说明：
- T-002 和 T-003 可在 T-001 完成后并行执行
- T-004 和 T-005 可在 T-002 完成后并行执行
- T-006 需等待 T-003、T-004、T-005 全部完成
- T-007 依赖 T-006

### 1.3 检查点 (id: section-1.3)

#### 检查点 1: 基础设施就绪 (id: section-1.3-check-1)

- **位置**: T-003 完成后
- **验证**: `pip install -e .` 成功，`import guard4promptattack` 成功，10 个单元测试通过
- **阻塞**: 未通过 → 不得进入核心逻辑阶段

#### 检查点 2: 核心逻辑可独立验证 (id: section-1.3-check-2)

- **位置**: T-005 完成后
- **验证**: 流式检测器 13 个测试通过，LLM 客户端在有 API Key 时通过
- **阻塞**: 未通过 → 不得进入组装阶段

#### 检查点 3: 端到端阻断率达标 (id: section-1.3-check-3)

- **位置**: T-007 完成后
- **验证**: 10 种已知攻击手法阻断率 >= 90%（9/10+），正常对话放行
- **阻塞**: 未通过 → 需回退到 T-003 调整金丝雀词设计

---

## 2. 任务摘要 (id: section-2)

### T-001: 项目骨架搭建 (id: task-T-001)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.1, @DESIGN:change-8 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 1 |
| **描述** | 创建 pyproject.toml 包配置、目录结构（guard4promptattack/、canary/、tests/）、占位 __init__.py |
| **依赖** | 无 |
| **产物** | `pyproject.toml`（新增）、`guard4promptattack/__init__.py`（新增）、`guard4promptattack/canary/__init__.py`（新增）、`tests/__init__.py`（新增） |
| **验收标准** | `pip install -e .` 后 `python -c "import guard4promptattack; print(guard4promptattack.__version__)"` 输出 `0.1.0` |

### T-002: 基础设施模块 (id: task-T-002)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.2-mod-config, @DESIGN:section-3.2-mod-exceptions, @DESIGN:section-3.2-mod-types, @DESIGN:FR-009, @DESIGN:FR-010 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 2 |
| **描述** | 实现 GuardConfig dataclass（8 字段）、load_config() 分层加载、3 个异常类、MatchResult dataclass；编写 config 测试验证默认值和环境变量覆盖 |
| **依赖** | T-001 |
| **产物** | `guard4promptattack/config.py`（新增）、`guard4promptattack/exceptions.py`（新增）、`guard4promptattack/types.py`（新增）、`tests/test_config.py`（新增） |
| **验收标准** | `pytest tests/test_config.py -v` 4 passed |

### T-003: 金丝雀提示词资产 (id: task-T-003)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.2-mod-prompt, @DESIGN:section-3.6, @DESIGN:FR-002, @DESIGN:FR-003 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 3 |
| **描述** | 实现 DEFAULT_CANARY_PROMPT（Zyphor-7X 虚构角色）和 DEFAULT_CANARY_WORDS（5 个金丝雀词 + 正则变体）；编写测试验证结构完整性和正则可编译性 |
| **依赖** | T-001 |
| **产物** | `guard4promptattack/canary/prompt.py`（新增）、`tests/test_prompt.py`（新增） |
| **验收标准** | `pytest tests/test_prompt.py -v` 6 passed；所有金丝雀词出现在提示词中，正则能匹配自身原文 |

### T-004: 流式检测器 (id: task-T-004)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.2-mod-detector, @DESIGN:section-3.3-flow-check, @DESIGN:FR-005, @DESIGN:FR-006 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 4 |
| **描述** | 实现 StreamDetector 类：累积文本缓冲、子串匹配（先）、正则匹配（后）、流式 feed 接口；编写 13 个测试覆盖无命中、精确匹配、大小写、正则变体、跨 chunk 累积 |
| **依赖** | T-002（types.py 的 MatchResult） |
| **产物** | `guard4promptattack/canary/detector.py`（新增）、`tests/test_detector.py`（新增） |
| **验收标准** | `pytest tests/test_detector.py -v` 13 passed |

### T-005: 金丝雀 LLM 流式客户端 (id: task-T-005)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.2-mod-llm, @DESIGN:section-4.2-ext-1, @DESIGN:FR-004, @DESIGN:FR-007, @DESIGN:FR-008 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 5 |
| **描述** | 实现 stream_canary_response() 异步生成器：httpx SSE 流式请求、OpenAI 兼容请求体、超时配置、SSE 行解析、异常转换；编写集成测试（有 CANARY_API_KEY 时真实调用，无时 skip） |
| **依赖** | T-002（config.py 的 GuardConfig 和 exceptions） |
| **产物** | `guard4promptattack/canary/llm.py`（新增）、`tests/test_llm.py`（新增） |
| **验收标准** | 有 CANARY_API_KEY 时 `pytest tests/test_llm.py -v` 7 passed；token 非空、max_tokens 限制生效、无效 key 抛 CanaryAPIError |

### T-006: check() 公开 API (id: task-T-006)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:section-3.2-mod-init, @DESIGN:section-3.7, @DESIGN:FR-001, @DESIGN:section-3.3-flow-check |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 6 |
| **描述** | 覆盖 __init__.py 占位为完整实现：check() 函数组装配置解析 → 检测器初始化 → LLM 流式调用 + 实时检测 → bool 返回；处理 fail_closed 策略和事件循环兼容（同步/异步上下文均可调用） |
| **依赖** | T-002, T-003, T-004, T-005 |
| **产物** | `guard4promptattack/__init__.py`（修改） |
| **验收标准** | `python -c "from guard4promptattack import check; print('OK')"` 成功 |

### T-007: 端到端冒烟测试 (id: task-T-007)

| 字段 | 内容 |
|------|------|
| **关联设计** | @DESIGN:NFR-001, @DESIGN:NFR-002, @DESIGN:section-1.2 |
| **Superpowers 任务** | @SP:plan/2026-06-21-guard4promptattack-mvp Task 7 |
| **描述** | 编写端到端测试：3 个正常对话案例（应返回 False）、10 种已知提示词攻击手法（应返回 True）、错误处理路径（ConfigurationError 抛出）；测试在有 CANARY_API_KEY 时真实执行 |
| **依赖** | T-006 |
| **产物** | `tests/test_check.py`（新增） |
| **验收标准** | 正常对话 3/3 返回 False，攻击手法 >= 9/10 返回 True（90%+ 阻断率） |

---

## 3. 环境与工具 (id: section-3)

| 依赖 | 版本 | 用途 |
|------|------|------|
| Python | >= 3.10 | 运行环境 |
| httpx | >= 0.27.0 | SSE 流式 HTTP 客户端 |
| pytest | >= 8.0 | 测试框架 |

| 工具 | 用途 |
|------|------|
| pip | 包安装与管理 |
| git | 版本控制，每任务提交 |

| 环境变量 | 用途 |
|----------|------|
| CANARY_API_KEY | 金丝雀 LLM API 密钥（必填，无此变量时集成测试自动 skip） |

---

## 附录 A：追溯索引 (id: appendix-a)

| 锚点 ID | 条目 | 供后续引用 |
|----------|------|-----------|
| task-T-001 | 项目骨架搭建 | @PLAN:task-T-001 |
| task-T-002 | 基础设施模块 | @PLAN:task-T-002 |
| task-T-003 | 金丝雀提示词资产 | @PLAN:task-T-003 |
| task-T-004 | 流式检测器 | @PLAN:task-T-004 |
| task-T-005 | 金丝雀 LLM 流式客户端 | @PLAN:task-T-005 |
| task-T-006 | check() 公开 API | @PLAN:task-T-006 |
| task-T-007 | 端到端冒烟测试 | @PLAN:task-T-007 |
| section-1.3-check-1 | 检查点 1: 基础设施就绪 | @PLAN:section-1.3-check-1 |
| section-1.3-check-2 | 检查点 2: 核心逻辑可独立验证 | @PLAN:section-1.3-check-2 |
| section-1.3-check-3 | 检查点 3: 端到端阻断率达标 | @PLAN:section-1.3-check-3 |

---

## 附录 B：设计覆盖矩阵 (id: appendix-b)

| 设计条目 | 锚点 | 对应任务 | 覆盖状态 |
|----------|------|----------|----------|
| 背景与动机 | @DESIGN:section-1.1 | T-001~T-007 | 已覆盖 |
| 目标与非目标 | @DESIGN:section-1.2 | T-001~T-007 | 已覆盖 |
| 范围边界 | @DESIGN:section-1.3 | T-001~T-007 | 已覆盖 |
| 关键术语 | @DESIGN:section-1.4 | T-003, T-004, T-006 | 已覆盖 |
| FR-001 公共检测 API | @DESIGN:FR-001 | T-006 | 已覆盖 |
| FR-002 内置默认金丝雀资产 | @DESIGN:FR-002 | T-003 | 已覆盖 |
| FR-003 自定义金丝雀资产 | @DESIGN:FR-003 | T-006 | 已覆盖 |
| FR-004 独立 API 配置 | @DESIGN:FR-004 | T-002, T-005 | 已覆盖 |
| FR-005 流式调用与实时检测 | @DESIGN:FR-005 | T-004, T-005, T-006 | 已覆盖 |
| FR-006 子串 + 正则双重检测 | @DESIGN:FR-006 | T-004 | 已覆盖 |
| FR-007 最大输出 token 限制 | @DESIGN:FR-007 | T-005 | 已覆盖 |
| FR-008 超时与截断 | @DESIGN:FR-008 | T-005, T-006 | 已覆盖 |
| FR-009 分层配置加载 | @DESIGN:FR-009 | T-002 | 已覆盖 |
| FR-010 fail_closed 策略 | @DESIGN:FR-010 | T-002, T-006 | 已覆盖 |
| NFR-001 攻击阻断率 | @DESIGN:NFR-001 | T-007 | 已覆盖 |
| NFR-002 误检率 | @DESIGN:NFR-002 | T-007 | 已覆盖 |
| NFR-003 延迟上限 | @DESIGN:NFR-003 | T-002, T-005 | 已覆盖 |
| NFR-004 确定性行为 | @DESIGN:NFR-004 | T-005 | 已覆盖 |
| 约束条件 | @DESIGN:section-2.3 | T-001, T-005 | 已覆盖 |
| 架构概览 | @DESIGN:section-3.1 | T-001 | 已覆盖 |
| 模块 __init__.py | @DESIGN:section-3.2-mod-init | T-006 | 已覆盖 |
| 模块 canary/prompt.py | @DESIGN:section-3.2-mod-prompt | T-003 | 已覆盖 |
| 模块 canary/llm.py | @DESIGN:section-3.2-mod-llm | T-005 | 已覆盖 |
| 模块 canary/detector.py | @DESIGN:section-3.2-mod-detector | T-004 | 已覆盖 |
| 模块 config.py | @DESIGN:section-3.2-mod-config | T-002 | 已覆盖 |
| 模块 exceptions.py | @DESIGN:section-3.2-mod-exceptions | T-002 | 已覆盖 |
| 模块 types.py | @DESIGN:section-3.2-mod-types | T-002 | 已覆盖 |
| 流程 check() 执行路径 | @DESIGN:section-3.3-flow-check | T-006 | 已覆盖 |
| 决策 1: 独立 API 配置 | @DESIGN:section-3.4-decision-1 | T-002, T-005 | 已覆盖 |
| 决策 2: 检测方式 | @DESIGN:section-3.4-decision-2 | T-004 | 已覆盖 |
| 决策 3: fail_closed | @DESIGN:section-3.4-decision-3 | T-006 | 已覆盖 |
| 决策 4: 不做预筛 | @DESIGN:section-3.4-decision-4 | T-006（未实现即覆盖） | 已覆盖 |
| 决策 5: temperature=0 | @DESIGN:section-3.4-decision-5 | T-005 | 已覆盖 |
| 接口 init → llm | @DESIGN:section-4.1-iface-1 | T-005, T-006 | 已覆盖 |
| 接口 init → detector | @DESIGN:section-4.1-iface-2 | T-004, T-006 | 已覆盖 |
| 接口 init → prompt | @DESIGN:section-4.1-iface-3 | T-003, T-006 | 已覆盖 |
| 外部 API: 金丝雀 LLM | @DESIGN:section-4.2-ext-1 | T-005 | 已覆盖 |
| 风险 1: LLM 拒绝回答 | @DESIGN:section-5.1-risk-1 | T-003, T-007 | 已覆盖 |
| 风险 2: 编码绕过 | @DESIGN:section-5.1-risk-2 | T-007（验证） | 已覆盖 |
| 风险 3: 金丝雀词偶然出现 | @DESIGN:section-5.1-risk-3 | T-003 | 已覆盖 |
| 风险 4: 正则过于宽泛 | @DESIGN:section-5.1-risk-4 | T-004 | 已覆盖 |
| 变更 change-1 (config.py) | @DESIGN:change-1 | T-002 | 已覆盖 |
| 变更 change-2 (exceptions.py) | @DESIGN:change-2 | T-002 | 已覆盖 |
| 变更 change-3 (types.py) | @DESIGN:change-3 | T-002 | 已覆盖 |
| 变更 change-4 (prompt.py) | @DESIGN:change-4 | T-003 | 已覆盖 |
| 变更 change-5 (llm.py) | @DESIGN:change-5 | T-005 | 已覆盖 |
| 变更 change-6 (detector.py) | @DESIGN:change-6 | T-004 | 已覆盖 |
| 变更 change-7 (__init__.py) | @DESIGN:change-7 | T-006 | 已覆盖 |
| 变更 change-8 (pyproject.toml) | @DESIGN:change-8 | T-001 | 已覆盖 |

**覆盖结论**：所有 49 个设计锚点均已覆盖，无遗漏。
