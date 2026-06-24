# 论文修正方案

## 修正原则

1. **诚实优先**：不在 DeepSeek 上假赢，不在 Qwen-only 上伪装
2. **数据驱动**：所有声明必须有新实验数据支撑
3. **审稿导向**：逐一回应审批意见中的 CRITICAL/MAJOR 问题
4. **技术准确**：修正「token 级」→「字符串级」措辞，澄清 RefusalDetector 状态

---

## 逐节修正清单

### Abstract
- [ ] 更新数据：216 正常样本、3 折 CV、TNR CI [90.7%,100%]
- [ ] 加入统计检验提及
- [ ] 加入多轮免疫实验结论
- [ ] 保留金丝雀类比（审稿人认可）

### 1. Introduction
- [ ] 修正新颖性声明：「独立代理+单轮无上下文+输出行为观察」→ 改为「将检测逻辑通过内嵌标记词编码进金丝雀提示词」
- [ ] 补充引用：LlamaGuard, NeMo Guardrails, StruQ/SecAlign
- [ ] 加入与嵌入方法的定位差异（望文生义 vs 行为观察）
- [ ] 加入多轮免疫实验的预告

### 2. Related Work
- [ ] 补充代理检测类：LlamaGuard, NeMo Guardrails
- [ ] 补充安全对齐类：StruQ/SecAlign, SysVec
- [ ] 补充嵌入/分类类：sentence-BERT 等（作为区分）
- [ ] 深化 little-canary 对比（三处差异：外部分析器 vs 内嵌标记、通用注入 vs 聚焦套取、block/flag/pass vs 二值检测）
- [ ] 修正 Canari/Rebuff 引用：提供版本号和访问日期

### 3. Method
- [ ] 3.2: 修正「token 级流式匹配」→「字符串级累积子串匹配」
- [ ] 3.4: 澄清 RefusalDetector 已从 check() 中移除，功能被标记词统一
- [ ] 3.4: 补充 fail_closed 导致的全量误判说明（Ollama 宕机时）
- [ ] 可选：增加「为什么不是语义嵌入」小节，与 TF-IDF 基线形成对比论证

### 4. Experiments
- [ ] 4.1 数据集：更新为 216 正常（12 类）+ 54 攻击，3 折分层 CV
- [ ] 4.1 基线：增加 TF-IDF、KeywordWeight 中间复杂度基线
- [ ] 4.1 评估指标：增加 McNemar 检验、Clopper-Pearson CI、Bootstrap F1 CI
- [ ] 4.2 主对比实验：用 3 折均值±标准差替换原 N=1 结果
  - Table 1: Ours 0.864±0.027, LLM-Judge 0.700±0.121, TF-IDF 0.743, RegexGuard 0.727, KeywordWeight 0.441
  - TNR 95% CI 从 [83.9%,100%] 缩窄到 [90.7%,100%]
- [ ] 4.2 诚实报告：在 Table 1 脚注中注明仅 Qwen 模型族验证
- [ ] 4.3 消融实验：保留 Table 2（已正确区分 Natural-Only/Marker-Only/Dual）
- [ ] 4.4 模型非单调性：保留，补充 DeepSeek 上 LLM-Judge F1=0.981 > Ours 0.860
  - **关键修改**：将 DeepSeek 结果提升到 Table 中，不再隐藏在定性讨论
- [ ] 4.5 新增：多轮攻击上下文免疫实验
  - Table: 零上下文 100% vs 完整上下文 60%（McNemar p=0.046）
  - 4 个漏检的根因分析（正确拒绝但未插入标记词）
- [ ] 4.6 新增：中间基线对比分析（TF-IDF vs Ours 的哲学差异）

### 5. Discussion
- [ ] 5.1: 保留金丝雀代价讨论
- [ ] 5.2: 保留不可替代场景
- [ ] 5.3: 更新局限
  - 仅 Qwen 验证 → 承认
  - 多轮实验 → 已有数据支撑
  - 行为传递假设 → 承认未验证
  - 新增：标记合规性受上下文干扰（多轮实验发现）
  - 新增：延迟-精度 tradeoff（9B 2.7s vs RegexGuard 0ms）

### 6. Conclusion
- [ ] 缩小结论范围：从「非对称代理检测框架」→「金丝雀标记词检测机制」
- [ ] 强调行为观察 vs 统计相似的核心理念差异

### References
- [ ] 新增：Meta Llama Prompt Guard (2024)
- [ ] 新增：NVIDIA NeMo Guardrails
- [ ] 新增：StruQ/SecAlign (USENIX Security 2025)
- [ ] 新增：SysVec (CCS 2025)
- [ ] 新增：ProxyPrompt (2025)
- [ ] 修正：Canari/Rebuff 加版本号和访问日期
- [ ] 保留：PromptKeeper, Raccoon, Prompt Leakage, little-canary 等

---

## 执行顺序

Section 1 (Abstract) → 2 (Introduction) → 3 (Related Work) → 4 (Method) → 5 (Experiments) → 6 (Discussion) → 7 (Conclusion) → 8 (References)
