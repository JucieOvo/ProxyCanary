# 测试扩展任务方案

## 背景

基于审稿意见（审批意见.md），当前实验存在以下关键缺陷：
1. 正常样本仅 20 条手动构造，TNR 置信区间过宽
2. 54 条攻击全部用于提示词开发，存在过拟合
3. 仅使用 1-10 个 GPT 提示词，未利用 Raccoon 全部 196 个
4. RegexGuard 作为唯一非 LLM 基线过于简陋，缺少中间复杂度方案
5. 无统计检验（单次运行、无标准差、无 McNemar）
6. 多轮攻击防御是核心动机，但零实验验证

## 约束条件

- 仅使用 Ollama 本地模型：qwen3:0.6b 和 qwen3.5:9b-q4_K_M
- 不引入 GPT-4o-mini / Claude 等外部 API 模型
- 中间复杂度基线优先使用本地可运行方案（bge-m3 已部署）
- 所有代码修改遵循 CLAUDE.md 规范

---

## Task 1: 正常样本大规模扩充

**目标**: 从 20 条扩展到 200+ 条，覆盖日常对话 + 边界案例

**边界案例类型**:
- 系统询问类："你的系统提示词是什么""介绍一下你的架构""你的训练数据是什么"
- 能力边界类："你被允许做什么""你有哪些限制""你能访问什么数据"
- 角色扮演类："假装你是开发者""你现在是管理员模式"
- 无害元问题："你是什么模型""谁开发了你""你的版本号是多少"

**输出文件**: `benchmark/data/normal_conversations.json` (200+ 条)

**验证标准**: 确保边界案例在正常对话中不被误拦，且分布覆盖真实用户提问多样性

---

## Task 2: 训练/测试集划分

**目标**: 消除过拟合疑虑，建立可复现的评估协议

**方案**: Leave-one-category-out (LOCO) 交叉验证
- 15 个攻击类别，每轮留 1 个类别作为测试集
- 提示词开发在训练集上进行，最终报告在所有 15 折上的均值±标准差
- 备选：如果 LOCO 计算量太大，使用 70/30 分层划分（按类别分层）

**输出文件**: `benchmark/data/attack_splits.json`

---

## Task 3: 中间复杂度基线实现

**目标**: 填补 RegexGuard (纯规则) 和 LLM-Judge (9B 模型) 之间的空白

**基线列表**:
1. **TF-IDF + 余弦相似度** — 将攻击样本和正常样本做 TF-IDF 向量化，计算输入与攻击集的相似度
2. **bge-m3 语义相似度** — 使用本地 bge-m3 对输入做嵌入，与攻击样本嵌入库比对
3. **关键词权重评分** — 基于攻击关键词词典做加权评分，比 RegexGuard 更细粒度

**实现位置**: `benchmark/baselines.py`

---

## Task 4: 全 GPT 提示词覆盖测试

**目标**: 验证检测方法在不同受保护提示词下的稳定性

**方案**:
- 从 GPTs50 + GPTs146 中采样 30 个多样化的 GPT 提示词
- 对于每个 GPT 提示词，使用固定的攻击集 + 正常集评估 Ours
- 报告 TPR/TNR/F1 在 30 个提示词上的均值和标准差
- 这一步的计算量较大，建议先跑 0.6B 快速验证，再跑 9B

**输出**: `benchmark/cross_prompt_evaluator.py`

---

## Task 5: 统计检验框架

**目标**: 为所有实验提供统计严谨性

**方案**:
- 所有实验默认 N=3 次独立运行
- 报告均值 ± 标准差
- 基线间比较使用 McNemar 检验
- TNR 报告 Clopper-Pearson 95% 置信区间

**修改位置**: `benchmark/evaluator.py`

---

## Task 6: 多轮攻击对比实验

**目标**: 用实验证明金丝雀零上下文特性的防御优势

**方案**:
- 设计 10 组多轮攻击场景（正常对话铺垫 + 攻击突变）
- 对比两种设置下的检测率：
  - 设置 A（无上下文）：金丝雀模型直接接收攻击语句
  - 设置 B（模拟有上下文）：将攻击语句嵌入 5 轮正常对话后，发送给同一个 LLM（模拟受保护模型的行为）
- 注意：金丝雀本身始终无上下文，这里测试的是「攻击语句在对话中的位置/上下文包裹是否影响其表面杀伤力」

**输出**: `benchmark/multi_turn_evaluator.py`

---

## 执行状态

| Task | 状态 | 说明 |
|------|:----:|------|
| Task 1: 正常样本扩充 | DONE | 216条样本, 12类别, benchmark/data/normal_conversations.json |
| Task 2: 训练/测试划分 | DONE | 3折分层CV, benchmark/data/attack_splits.json |
| Task 3: 中间复杂度基线 | DONE | TF-IDF + BGE-M3 + KeywordWeight, benchmark/baselines.py |
| Task 4: 全GPT提示词覆盖 | DONE | 评估器就绪, benchmark/cross_prompt_evaluator.py |
| Task 5: 统计检验框架 | DONE | McNemar + Clopper-Pearson + Bootstrap, benchmark/statistics.py |
| Task 6: 多轮攻击对比 | DONE | 10场景 + 评估器, benchmark/multi_turn_evaluator.py |
