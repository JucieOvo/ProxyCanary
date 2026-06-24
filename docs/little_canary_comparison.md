# Guard4PromptAttack vs little-canary: 差异分析

## 相同点

两者都使用了"牺牲性金丝雀模型前置检测"范式：
- 独立小模型在受保护模型之前接收用户输入
- 观察金丝雀模型的响应行为判断安全性
- 基于 Ollama 本地部署
- fail-open 设计（金丝雀不可用时放行）
- API 风格：check(input) → 安全/不安全

## 差异点

### 1. 检测目标

| little-canary | Guard4PromptAttack |
|---------------|-------------------|
| 通用 Prompt Injection（注入攻击、越狱、角色劫持等） | **聚焦 Prompt Extraction**（提示词套取） |
| 评估：自建 160 条红队测试集 + TensorTrust | 评估：**Raccoon 同行评审基准**（ACL 2024, 14类攻击） |

### 2. 检测架构

```
little-canary (3层):
  用户输入 → [结构过滤器: 正则+解码重检] → [金丝雀探针] → [外部分析器: 正则或LLM Judge] → 判定

Guard4PromptAttack (1层):
  用户输入 → [金丝雀探针: 内嵌标记词] → [StreamDetector: 实时token级匹配] → 判定
```

**核心差异**：little-canary 需要一个独立的外部分析器（BehavioralAnalyzer 做正则模式匹配金丝雀输出，或 LLMJudge 做二分类）来判断金丝雀响应是否异常。Guard4PromptAttack 将检测逻辑嵌入金丝雀提示词本身——标记词和金丝雀词一起被 StreamDetector 在流式输出中实时捕获，**无需外部分析器**。

### 3. 金丝雀提示词设计

| little-canary | Guard4PromptAttack |
|---------------|-------------------|
| 中性提示词："你是一个有帮助的助手，清晰简洁地回答问题" | **主动设计**：嵌入虚构参数 + 标记词指令 |
| 不修改金丝雀行为 | **主动诱导两条响应路径**：泄露路径输出参数 / 拒绝路径嵌入标记 |
| 依赖外部分析器判断输出是否异常 | 检测逻辑在提示词内闭环——StreamDetector 简单匹配 |

### 4. 拒绝信号处理

- **little-canary**: 无拒绝检测机制。模型的安全拒绝被外部分析器视为正常响应。
- **Guard4PromptAttack**: 通过"No Way I Cant"标记词将拒绝行为统一到检测路径中。消融证实标记词贡献77.8% TPR。

### 5. 系统化评估

| | little-canary | Guard4PromptAttack |
|---|---------------|-------------------|
| 基准 | 自建160条 + TensorTrust 400条 | **Raccoon** (ACL 2024 Findings, 同行评审) |
| 基线对比 | 无系统基线 | **5基线**：NoDefense, RegexGuard, CanariToken, LLM-Judge, Ours |
| 消融 | 无 | **双路径消融**：Natural-Only vs Marker-Only vs Dual |
| 模型对比 | qwen2.5:1.5b | 0.6B + 9B 双模型对比 |
| 记录 | 无 | **592条完整记录** + SafeDetector异常计数 |

### 6. 模型能力非单调性

Guard4PromptAttack 首次报告了门控模型能力与检测效果之间的非单调关系：
- 弱模型（0.6B）需要对抗式提示词（v4 F1=0.889）
- 强模型（9B）需要非对抗式提示词（v6 F1=0.887）
- 同一提示词在9B上0.931→0.6B上0.377（v6跨模型崩溃）

little-canary 未涉及此维度。

### 7. 工程成熟度 vs 研究深度

| little-canary | Guard4PromptAttack |
|---------------|-------------------|
| PyPI 包，CI/CD，文档完善 | 研究原型 |
| 可插拔提供商（Ollama/OpenAI） | 模块化但未发布为包 |
| 3种部署模式（block/advisory/full） | 单一检测API |

## 对论文的意义

little-canary 验证了牺牲性金丝雀模型的可行性——我们不需要重新证明这个范式的合理性。我们的贡献是在此基础上：

1. **更简洁的检测机制**：消除外部分析器，将检测逻辑内嵌提示词
2. **特定攻击场景的聚焦**：提示词套取而非通用注入
3. **同行评审基准上的系统化验证**：Raccoon + 5基线 + 消融
4. **新的科学发现**：模型能力与检测效果的非单调关系

论文应明确引用 little-canary 作为 prior art，并在 Related Work 中诚实讨论异同。
