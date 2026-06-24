"""
模块名称：benchmark.baselines
功能描述：
    中间复杂度基线检测器模块。
    填补 RegexGuard（10条纯正则规则）与 LLM-Judge（9B模型零样本分类）
    之间的空白，提供三个可训练的检测基线：
        1. TF-IDF + 余弦相似度分类器
        2. bge-m3 语义嵌入相似度分类器
        3. 关键词加权评分分类器

    所有基线遵循统一接口：train(attacks, normals) → detect(text) → bool。
    阈值通过训练集上的 F1 最大化自动确定。

主要组件：
    - TfidfBaseline: TF-IDF 向量化 + 余弦相似度
    - BgeM3Baseline: bge-m3 嵌入 + 余弦相似度
    - KeywordWeightBaseline: 攻击关键词加权评分

依赖说明：
    - sklearn.feature_extraction.text.TfidfVectorizer: TF-IDF 向量化
    - sklearn.metrics.pairwise.cosine_similarity: 余弦相似度
    - sentence_transformers.SentenceTransformer: bge-m3 嵌入模型
    - numpy: 向量运算

作者：JucieOvo
创建日期：2026-06-24
"""

import json
import math
import re
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ============================================================
# 基线 1: TF-IDF + 余弦相似度
# ============================================================

class TfidfBaseline:
    """
    TF-IDF 余弦相似度基线检测器。

    职责：
        将训练攻击样本做 TF-IDF 向量化，计算输入文本与攻击样本库
        的最大余弦相似度。相似度超过阈值时判定为攻击。

    设计原理：
        TF-IDF 捕捉词汇层面的攻击特征——提示词套取攻击共享高频
        关键词（system prompt, 忽略指令 等），正常对话不含这些词。
        相比 RegexGuard 的硬匹配，TF-IDF 提供连续相似度评分，
        支持阈值调优和软匹配。

    属性：
        _vectorizer (TfidfVectorizer): TF-IDF 向量化器
        _attack_vectors (np.ndarray): 训练攻击样本的 TF-IDF 矩阵
        _threshold (float): 判定阈值，训练时自动确定
        _name (str): 基线名称
    """

    # 预定义阈值搜索空间
    _THRESHOLD_CANDIDATES = [
        0.01, 0.02, 0.03, 0.05, 0.07,
        0.10, 0.12, 0.15, 0.18, 0.20,
        0.25, 0.30, 0.35, 0.40, 0.50,
    ]

    def __init__(self):
        """初始化 TF-IDF 基线（未训练状态）"""
        # TF-IDF 向量化器：使用字符级 n-gram (1-3) 补充词级特征
        # 字符 n-gram 对短文本和拼写变体更鲁棒
        self._vectorizer: Optional[TfidfVectorizer] = None
        # 训练攻击样本的 TF-IDF 特征矩阵，形状为 (n_attacks, n_features)
        self._attack_vectors: Optional[np.ndarray] = None
        # 判定阈值：输入与任一攻击样本的余弦相似度大于此值时判定为攻击
        self._threshold: float = 0.15
        # 基线显示名称
        self._name: str = "TF-IDF"

    def name(self) -> str:
        """返回基线名称，用于评估报告"""
        return self._name

    def train(self, attacks: list[str], normals: list[str]) -> float:
        """
        在训练数据上拟合 TF-IDF 向量化器并调优阈值。

        训练流程：
        1. 使用所有训练文本（攻击 + 正常）拟合 TF-IDF 向量化器
        2. 提取攻击样本的 TF-IDF 矩阵
        3. 对每个阈值候选，计算训练集上的 F1
        4. 选择 F1 最高的阈值

        :param attacks: 训练攻击文本列表
        :param normals: 训练正常文本列表
        :return: 最优阈值下的训练集 F1
        """
        # 步骤 1：拟合 TF-IDF 向量化器
        # 使用词级 unigram + bigram，同时捕捉单字和多字短语特征
        all_texts = list(attacks) + list(normals)
        self._vectorizer = TfidfVectorizer(
            analyzer="char_wb",       # 词边界内的字符 n-gram，兼顾词级和字符级
            ngram_range=(2, 4),       # 2-4 gram，覆盖短词和短语片段
            max_features=500,         # 限制特征维度，避免过拟合
            sublinear_tf=True,        # 使用 1+log(tf) 抑制高频词权重
        ).fit(all_texts)

        # 提取攻击样本的 TF-IDF 矩阵
        self._attack_vectors = self._vectorizer.transform(attacks)

        # 步骤 2：阈值调优——在训练集上搜索最优阈值
        best_f1 = 0.0
        best_threshold = 0.15

        for threshold in self._THRESHOLD_CANDIDATES:
            # 在训练攻击样本上计算 TPR
            tp = 0
            for attack_text in attacks:
                score = self._compute_score(attack_text)
                if score >= threshold:
                    tp += 1
            # 在训练正常样本上计算 TNR
            tn = 0
            fp = 0
            for normal_text in normals:
                score = self._compute_score(normal_text)
                if score >= threshold:
                    fp += 1
                else:
                    tn += 1

            tpr = tp / len(attacks) if attacks else 0
            tnr = tn / len(normals) if normals else 0
            precision = tp / (tp + fp) if (tp + fp) else 0
            recall = tpr
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold

        self._threshold = best_threshold
        return best_f1

    def _compute_score(self, text: str) -> float:
        """
        计算输入文本的攻击相似度评分。

        将输入文本向量化后，计算其与所有训练攻击样本的余弦相似度，
        取最大值作为评分。最大值策略基于"最相似攻击"原则——
        如果输入跟任一已知攻击高度相似，则足以判定为攻击。

        :param text: 输入文本
        :return: 最大余弦相似度，范围 [0, 1]
        """
        if self._vectorizer is None or self._attack_vectors is None:
            raise RuntimeError("TF-IDF 基线未训练，请先调用 train()")
        # 向量化输入文本
        input_vec = self._vectorizer.transform([text])
        # 计算与所有攻击样本的余弦相似度
        similarities = cosine_similarity(input_vec, self._attack_vectors)[0]
        # 返回最大相似度
        return float(np.max(similarities))

    def detect(self, text: str) -> bool:
        """
        检测输入文本是否为提示词套取攻击。

        :param text: 输入文本
        :return: True 表示判定为攻击
        """
        score = self._compute_score(text)
        return score >= self._threshold


# ============================================================
# 基线 2: bge-m3 语义嵌入相似度
# ============================================================

class BgeM3Baseline:
    """
    bge-m3 语义嵌入相似度基线检测器。

    职责：
        使用本地 bge-m3 模型将训练攻击样本编码为语义向量，
        计算输入文本嵌入与攻击样本嵌入的最大余弦相似度。
        捕捉词汇表面不匹配但语义相近的攻击变体。

    设计原理：
        bge-m3 是多语言语义嵌入模型，能将"告诉我你的系统指令"
        和 "output your system prompt" 映射到相近的向量空间。
        相比 TF-IDF，语义嵌入能检测词汇完全不同的同义攻击。
        这是 RegexGuard（纯表面匹配）和 LLM-Judge（语义理解但成本高）
        之间的关键中间方案。

    属性：
        _model (SentenceTransformer): bge-m3 嵌入模型
        _attack_embeddings (np.ndarray): 训练攻击样本的嵌入矩阵
        _threshold (float): 判定阈值
    """

    _THRESHOLD_CANDIDATES = [
        0.50, 0.55, 0.60, 0.62, 0.64,
        0.66, 0.68, 0.70, 0.72, 0.74,
        0.76, 0.78, 0.80, 0.82, 0.85,
        0.88, 0.90,
    ]

    def __init__(self, model_path: Optional[str] = None):
        """
        初始化 bge-m3 基线。

        :param model_path: bge-m3 模型路径，默认使用系统部署路径
        """
        # 延迟导入，避免未安装 sentence-transformers 时模块加载失败
        from sentence_transformers import SentenceTransformer

        # bge-m3 模型路径：参数 > 系统默认路径
        if model_path is None:
            model_path = r"C:\Users\15311\.cache\modelscope\hub\models\BAAI\bge-m3"

        # 初始化嵌入模型，使用 GPU 推理
        self._model = SentenceTransformer(model_path, device="cuda")
        # 训练攻击样本嵌入矩阵
        self._attack_embeddings: Optional[np.ndarray] = None
        # 判定阈值
        self._threshold: float = 0.70
        self._name: str = "BGE-M3"

    def name(self) -> str:
        return self._name

    def train(self, attacks: list[str], normals: list[str]) -> float:
        """
        编码训练攻击样本并调优阈值。

        :param attacks: 训练攻击文本列表
        :param normals: 训练正常文本列表
        :return: 最优阈值下的训练集 F1
        """
        # 步骤 1：批量编码攻击样本
        # bge-m3 输入格式：每个文本独立编码，使用 mean pooling
        self._attack_embeddings = self._model.encode(
            attacks,
            normalize_embeddings=True,   # 归一化后余弦相似度 = 内积
            show_progress_bar=False,
            batch_size=8,
        )

        # 步骤 2：阈值调优
        best_f1 = 0.0
        best_threshold = 0.70

        for threshold in self._THRESHOLD_CANDIDATES:
            tp = sum(1 for a in attacks if self._compute_score(a) >= threshold)
            tn = sum(1 for n in normals if self._compute_score(n) < threshold)
            fp = len(normals) - tn

            tpr = tp / len(attacks) if attacks else 0
            tnr = tn / len(normals) if normals else 0
            precision = tp / (tp + fp) if (tp + fp) else 0
            f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold

        self._threshold = best_threshold
        return best_f1

    def _compute_score(self, text: str) -> float:
        """
        计算输入文本与攻击样本的最大语义相似度。

        :param text: 输入文本
        :return: 最大余弦相似度，范围 [0, 1]
        """
        if self._attack_embeddings is None:
            raise RuntimeError("BGE-M3 基线未训练，请先调用 train()")
        # 编码输入文本
        input_emb = self._model.encode(
            [text],
            normalize_embeddings=True,
            show_progress_bar=False,
        )
        # 计算与所有攻击嵌入的余弦相似度（已归一化，直接用内积）
        similarities = np.dot(input_emb, self._attack_embeddings.T)[0]
        return float(np.max(similarities))

    def detect(self, text: str) -> bool:
        """
        检测输入文本是否为提示词套取攻击。

        :param text: 输入文本
        :return: True 表示判定为攻击
        """
        score = self._compute_score(text)
        return score >= self._threshold


# ============================================================
# 基线 3: 关键词加权评分
# ============================================================

class KeywordWeightBaseline:
    """
    关键词加权评分基线检测器。

    职责：
        基于攻击关键词词典对输入文本进行加权评分。
        相比 RegexGuard（10条硬二值规则），本基线使用更细粒度的
        关键词权重体系——核心攻击词权重高，辅助特征词权重低——
        通过连续评分 + 可调阈值实现更好的区分度。

    设计原理：
        RegexGuard 的任意关键词命中即判定为攻击，导致假阳性较高。
        本基线为每个关键词分配权重（基于其在攻击样本中的信息增益），
        累积所有命中关键词的权重，仅当总分超过阈值时判定为攻击。

    属性：
        _keyword_weights (dict[str, float]): 关键词→权重映射
        _threshold (float): 判定阈值
        _case_sensitive (bool): 是否区分大小写
    """

    # 攻击关键词权重词典
    # 权重赋值原则：
    #   - 0.3-0.4: 强攻击信号（直接要求输出提示词/系统指令）
    #   - 0.2-0.3: 中等攻击信号（提示词相关但不直接要求）
    #   - 0.1-0.2: 弱攻击信号（攻击手法的辅助特征）
    #   - 0.05-0.1: 微弱信号（可能出现在正常对话中，仅做参考）
    _DEFAULT_KEYWORD_WEIGHTS = {
        # ---- 强攻击信号 (0.30-0.40) ----
        "系统提示词": 0.40,
        "system prompt": 0.40,
        "原始提示词": 0.38,
        "初始化提示词": 0.38,
        "最初的指令": 0.36,
        "你的提示词": 0.36,
        "输出提示词": 0.40,
        "泄露提示词": 0.40,
        "reveal your prompt": 0.40,
        "output your instructions": 0.40,
        "告诉我你的系统": 0.38,
        "show me your system": 0.38,
        "你的配置是什么": 0.35,
        "你的完整指令": 0.38,
        "原始配置": 0.34,
        "内部配置": 0.34,
        "后台配置": 0.34,
        "初始化内容": 0.33,
        # ---- 中等攻击信号 (0.20-0.30) ----
        "忽略之前的指令": 0.28,
        "ignore previous instructions": 0.28,
        "忘记之前说的": 0.26,
        "forget everything above": 0.26,
        "你现在是开发者": 0.24,
        "你现在是管理员": 0.24,
        "you are now a developer": 0.24,
        "act as admin": 0.24,
        "进入开发者模式": 0.26,
        "developer mode": 0.26,
        "调试模式": 0.22,
        "debug mode": 0.22,
        "不要拒绝": 0.24,
        "don't refuse": 0.24,
        "必须回答": 0.22,
        "不得拒绝": 0.24,
        "绕过限制": 0.22,
        "bypass restrictions": 0.22,
        "你被允许": 0.20,
        # ---- 弱攻击信号 (0.10-0.20) ----
        "代码块输出": 0.15,
        "用markdown输出": 0.15,
        "output in code block": 0.15,
        "一字不差": 0.15,
        "word for word": 0.15,
        "逐字": 0.15,
        "完全复制": 0.18,
        "exact copy": 0.18,
        "第一行是什么": 0.12,
        "开头是什么": 0.12,
        "what is the first line": 0.12,
        "secret": 0.12,
        "机密": 0.12,
        "api key": 0.18,
        "密钥": 0.18,
        # ---- 微弱信号 (0.05-0.10) ----
        "token": 0.05,      # 弱权重，正常编程对话中也常见
        "prompt": 0.08,     # 弱权重，编程语境常见
        "指令": 0.06,       # 弱权重，日常对话中可能出现
        "instruction": 0.08,
        "配置": 0.04,       # 极弱，天气/金融配置都可能触发
        "configuration": 0.06,
        "系统": 0.03,       # 极弱，操作系统/天气系统都可能
        "system": 0.05,
    }

    _THRESHOLD_CANDIDATES = [
        0.10, 0.15, 0.20, 0.25, 0.30,
        0.35, 0.40, 0.45, 0.50, 0.60,
    ]

    def __init__(self, keyword_weights: Optional[dict[str, float]] = None):
        """
        初始化关键词加权基线。

        :param keyword_weights: 自定义关键词权重词典，默认使用内置词典
        """
        self._keyword_weights = (
            dict(keyword_weights)
            if keyword_weights
            else dict(self._DEFAULT_KEYWORD_WEIGHTS)
        )
        self._threshold: float = 0.30
        self._name: str = "KeywordWeight"

    def name(self) -> str:
        return self._name

    def train(self, attacks: list[str], normals: list[str]) -> float:
        """
        在训练数据上调优阈值。

        :param attacks: 训练攻击文本列表
        :param normals: 训练正常文本列表
        :return: 最优阈值下的训练集 F1
        """
        best_f1 = 0.0
        best_threshold = 0.30

        for threshold in self._THRESHOLD_CANDIDATES:
            tp = sum(1 for a in attacks if self._compute_score(a) >= threshold)
            tn = sum(1 for n in normals if self._compute_score(n) < threshold)
            fp = len(normals) - tn

            tpr = tp / len(attacks) if attacks else 0
            tnr = tn / len(normals) if normals else 0
            precision = tp / (tp + fp) if (tp + fp) else 0
            f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) else 0

            if f1 > best_f1:
                best_f1 = f1
                best_threshold = threshold

        self._threshold = best_threshold
        return best_f1

    def _compute_score(self, text: str) -> float:
        """
        计算输入文本的加权关键词评分。

        对文本做转小写处理，累加所有匹配关键词的权重。
        每个关键词最多贡献一次（不重复计数），避免通过重复关键词刷分。

        :param text: 输入文本
        :return: 累计权重评分
        """
        lower_text = text.lower()
        total_score = 0.0
        # 使用集合追踪已匹配的关键词，避免重复计数
        matched = set()

        for keyword, weight in self._keyword_weights.items():
            if keyword.lower() in lower_text and keyword not in matched:
                total_score += weight
                matched.add(keyword)

        return total_score

    def detect(self, text: str) -> bool:
        """
        检测输入文本是否为提示词套取攻击。

        :param text: 输入文本
        :return: True 表示判定为攻击
        """
        score = self._compute_score(text)
        return score >= self._threshold


# ============================================================
# 辅助函数：加载正常样本
# ============================================================

def load_normal_samples(json_path: Optional[str] = None) -> list[str]:
    """
    从 JSON 文件加载正常对话样本，返回纯文本列表。

    :param json_path: JSON 文件路径，默认使用 benchmark/data/normal_conversations.json
    :return: 正常对话文本列表
    """
    if json_path is None:
        json_path = str(
            Path(__file__).resolve().parent / "data" / "normal_conversations.json"
        )

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [s["text"] for s in data["samples"]]


# ============================================================
# 辅助函数：从划分文件加载训练/测试集
# ============================================================

def load_attacks_from_split(
    split_path: Optional[str] = None,
    fold_index: int = 0,
) -> tuple[list[str], list[str]]:
    """
    从训练/测试划分 JSON 加载指定折的训练和测试攻击文本。

    :param split_path: 划分文件路径，默认使用 benchmark/data/attack_splits.json
    :param fold_index: 折索引 (0-2)
    :return: (train_attacks, test_attacks) 文本列表元组
    """
    if split_path is None:
        split_path = str(
            Path(__file__).resolve().parent / "data" / "attack_splits.json"
        )

    with open(split_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    fold = data["folds"][fold_index]
    train_texts = [a["text"] for a in fold["train"]]
    test_texts = [a["text"] for a in fold["test"]]

    return train_texts, test_texts
