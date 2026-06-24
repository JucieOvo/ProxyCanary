"""
模块名称：benchmark.statistics
功能描述：
    评估统计检验框架。
    提供 McNemar 配对检验、Clopper-Pearson 二项置信区间、
    以及 Bootstrap F1 置信区间等功能。
    用于评估检测基线间差异的统计显著性。

主要组件：
    - mcnemar_test: McNemar 配对检验（两个检测方法的配对比较）
    - clopper_pearson_ci: 二项比例的 Clopper-Pearson 精确置信区间
    - bootstrap_f1_ci: F1 分数的 Bootstrap 置信区间
    - StatisticalReport: 多基线统计对比报告

依赖说明：
    - scipy.stats: chi2 分布用于 McNemar 检验
    - numpy: 数值计算
    - statistics: 均值和标准差

作者：JucieOvo
创建日期：2026-06-24
"""

import statistics
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from scipy.stats import chi2


# ============================================================
# McNemar 配对检验
# ============================================================

@dataclass
class McNemarResult:
    """
    McNemar 检验结果。

    属性：
        statistic (float): 卡方统计量
        p_value (float): p 值
        significant (bool): 在 alpha=0.05 水平下是否显著
        n_ab (int): 方法 A 检出但 B 未检出的样本数
        n_ba (int): 方法 B 检出但 A 未检出的样本数
        total (int): 总样本数
    """
    statistic: float
    p_value: float
    significant: bool
    n_ab: int
    n_ba: int
    total: int
    description: str = ""


def mcnemar_test(
    y_true: list[bool],
    y_pred_a: list[bool],
    y_pred_b: list[bool],
    name_a: str = "Method A",
    name_b: str = "Method B",
    continuity_correction: bool = True,
) -> McNemarResult:
    """
    执行 McNemar 配对检验，判断两个检测方法在相同样本上的
    表现差异是否统计显著。

    McNemar 检验对比的是两个方法在相同样本上的不一致对：
    - n_ab: A 正确但 B 错误（A 优于 B）
    - n_ba: B 正确但 A 错误（B 优于 A）

    原假设 H0：两个方法的错误率相同
    备择假设 H1：两个方法的错误率不同

    使用连续性校正（Edwards 修正）以减少小样本下的 I 型错误率。

    限制条件：
    - 要求 n_ab + n_ba >= 25（否则使用二项精确检验更合适）
    - 仅适用于配对数据（同一组样本由两个方法独立评估）

    :param y_true: 真实标签列表
    :param y_pred_a: 方法 A 的预测列表
    :param y_pred_b: 方法 B 的预测列表
    :param name_a: 方法 A 名称
    :param name_b: 方法 B 名称
    :param continuity_correction: 是否使用连续性校正
    :return: McNemarResult 包含统计量、p 值和显著性别定
    """
    # 统计四个单元格的计数
    n_ab = 0  # A 对 B 错
    n_ba = 0  # B 对 A 错
    n_aa = 0  # 两者都对
    n_bb = 0  # 两者都错

    for true, pred_a, pred_b in zip(y_true, y_pred_a, y_pred_b):
        a_correct = (pred_a == true)
        b_correct = (pred_b == true)

        if a_correct and not b_correct:
            n_ab += 1
        elif not a_correct and b_correct:
            n_ba += 1
        elif a_correct and b_correct:
            n_aa += 1
        else:
            n_bb += 1

    total = len(y_true)

    # 计算 McNemar 卡方统计量
    # 仅考虑不一致对 (n_ab, n_ba)
    if continuity_correction and (n_ab + n_ba) > 0:
        # 使用连续性校正（Edwards 修正）
        statistic = (abs(n_ab - n_ba) - 1) ** 2 / (n_ab + n_ba)
    elif (n_ab + n_ba) > 0:
        # 无校正
        statistic = (n_ab - n_ba) ** 2 / (n_ab + n_ba)
    else:
        # 无不一致对，无法计算
        statistic = 0.0

    # 在 H0 下，统计量服从自由度为 1 的卡方分布
    if (n_ab + n_ba) > 0:
        p_value = 1.0 - chi2.cdf(statistic, df=1)
    else:
        p_value = 1.0

    significant = p_value < 0.05

    # 构建人类可读的描述
    if n_ab + n_ba == 0:
        desc = f"{name_a} 和 {name_b} 在所有 {total} 个样本上完全一致"
    elif significant:
        direction = f"{name_a} 优于 {name_b}" if n_ab > n_ba else f"{name_b} 优于 {name_a}"
        desc = (
            f"{direction}（McNemar 检验：不一致对 {n_ab} vs {n_ba}，"
            f"χ²={statistic:.2f}，p={p_value:.4f}）"
        )
    else:
        desc = (
            f"{name_a} 与 {name_b} 无显著差异"
            f"（不一致对 {n_ab} vs {n_ba}，χ²={statistic:.2f}，p={p_value:.4f}）"
        )

    return McNemarResult(
        statistic=statistic,
        p_value=p_value,
        significant=significant,
        n_ab=n_ab,
        n_ba=n_ba,
        total=total,
        description=desc,
    )


# ============================================================
# Clopper-Pearson 精确置信区间
# ============================================================

@dataclass
class BinomialCI:
    """
    二项比例的 Clopper-Pearson 置信区间。

    属性：
        proportion (float): 观测比例
        ci_lower (float): 下界
        ci_upper (float): 上界
        confidence_level (float): 置信水平（默认 0.95）
        n_success (int): 成功次数
        n_total (int): 总次数
    """
    proportion: float
    ci_lower: float
    ci_upper: float
    confidence_level: float
    n_success: int
    n_total: int

    def __repr__(self) -> str:
        return (
            f"{self.proportion:.1%} "
            f"[{self.ci_lower:.1%}, {self.ci_upper:.1%}] "
            f"({self.confidence_level:.0%} CI, n={self.n_total})"
        )


def clopper_pearson_ci(
    n_success: int,
    n_total: int,
    confidence_level: float = 0.95,
) -> BinomialCI:
    """
    计算二项比例的 Clopper-Pearson 精确置信区间。

    基于 Beta 分布：对于观测到 k 次成功、n 次试验，
    区间为 [Beta(α/2; k, n-k+1), Beta(1-α/2; k+1, n-k)]。

    与 Wald 正态近似不同，Clopper-Pearson 是保守的精确区间，
    保证覆盖率不低于名义置信水平。适用于小样本场景。

    使用场景：
    - TNR 置信区间：n_success = TN, n_total = TN + FP
    - TPR 置信区间：n_success = TP, n_total = TP + FN

    :param n_success: 成功次数（如 TN 或 TP）
    :param n_total: 总次数
    :param confidence_level: 置信水平，默认 0.95
    :return: BinomialCI 包含比例和置信区间
    """
    from scipy.stats import beta as beta_dist

    if n_total == 0:
        return BinomialCI(
            proportion=0.0,
            ci_lower=0.0,
            ci_upper=0.0,
            confidence_level=confidence_level,
            n_success=0,
            n_total=0,
        )

    alpha = 1.0 - confidence_level
    proportion = n_success / n_total

    # Beta(α/2; k, n-k+1) 和 Beta(1-α/2; k+1, n-k)
    # 边界处理：k=0 时下界为 0，k=n 时上界为 1
    if n_success == 0:
        ci_lower = 0.0
    else:
        ci_lower = beta_dist.ppf(alpha / 2, n_success, n_total - n_success + 1)

    if n_success == n_total:
        ci_upper = 1.0
    else:
        ci_upper = beta_dist.ppf(1 - alpha / 2, n_success + 1, n_total - n_success)

    return BinomialCI(
        proportion=proportion,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        confidence_level=confidence_level,
        n_success=n_success,
        n_total=n_total,
    )


# ============================================================
# Bootstrap F1 置信区间
# ============================================================

def bootstrap_f1_ci(
    y_true: list[bool],
    y_pred: list[bool],
    n_bootstrap: int = 2000,
    confidence_level: float = 0.95,
    seed: int = 42,
) -> tuple[float, float, float]:
    """
    使用 Bootstrap 方法估计 F1 分数的置信区间。

    Bootstrap 通过对原始评估数据做有放回重采样，
    模拟 F1 的抽样分布。不依赖正态假设，适用于
    小样本或非对称分布。

    算法：
    1. 从 (y_true, y_pred) 对中有放回采样 n 次
    2. 计算重采样后的 F1
    3. 重复 n_bootstrap 次
    4. 取 α/2 和 1-α/2 分位数作为置信区间

    :param y_true: 真实标签列表
    :param y_pred: 预测列表
    :param n_bootstrap: Bootstrap 重采样次数（建议 ≥1000）
    :param confidence_level: 置信水平
    :param seed: 随机种子
    :return: (f1_mean, ci_lower, ci_upper)
    """
    rng = np.random.RandomState(seed)
    n = len(y_true)

    # 计算原始 F1
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)

    def compute_f1(tp_val, fp_val, fn_val):
        precision = tp_val / (tp_val + fp_val) if (tp_val + fp_val) else 0
        recall = tp_val / (tp_val + fn_val) if (tp_val + fn_val) else 0
        return 2 * precision * recall / (precision + recall) if (precision + recall) else 0

    # Bootstrap 重采样
    indices = np.arange(n)
    true_arr = np.array(y_true, dtype=bool)
    pred_arr = np.array(y_pred, dtype=bool)
    f1_samples = np.zeros(n_bootstrap)

    for i in range(n_bootstrap):
        # 有放回采样
        boot_idx = rng.choice(indices, size=n, replace=True)
        boot_true = true_arr[boot_idx]
        boot_pred = pred_arr[boot_idx]

        tp_b = int(np.sum(boot_true & boot_pred))
        fp_b = int(np.sum(~boot_true & boot_pred))
        fn_b = int(np.sum(boot_true & ~boot_pred))

        f1_samples[i] = compute_f1(tp_b, fp_b, fn_b)

    # 取分位数
    alpha = 1.0 - confidence_level
    ci_lower = float(np.percentile(f1_samples, 100 * alpha / 2))
    ci_upper = float(np.percentile(f1_samples, 100 * (1 - alpha / 2)))
    f1_mean = float(np.mean(f1_samples))

    return f1_mean, ci_lower, ci_upper


# ============================================================
# 统计报告
# ============================================================

@dataclass
class StatisticalReport:
    """
    多基线统计对比报告。

    汇总多个基线的评估结果，包含：
    - 各基线的 TPR/TNR/F1 及置信区间
    - 各基线对之间的 McNemar 检验结果
    - Clopper-Pearson TNR 置信区间

    属性：
        baseline_names (list[str]): 基线名称列表
        metrics (dict): baseline_name → {tpr, tnr, f1, ...}
        mcnemar_matrix (dict): (baseline_a, baseline_b) → McNemarResult
        tnr_ci (dict): baseline_name → BinomialCI
    """
    baseline_names: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    mcnemar_results: list[McNemarResult] = field(default_factory=list)
    tnr_ci: dict = field(default_factory=dict)

    def add_baseline(
        self,
        name: str,
        y_true: list[bool],
        y_pred: list[bool],
    ):
        """
        添加一个基线的评估结果。

        :param name: 基线名称
        :param y_true: 真实标签列表
        :param y_pred: 预测列表（已从多次运行中聚合为最终判定）
        """
        self.baseline_names.append(name)

        # 计算混淆矩阵
        tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
        fp = sum(1 for t, p in zip(y_true, y_pred) if not t and p)
        tn = sum(1 for t, p in zip(y_true, y_pred) if not t and not p)
        fn = sum(1 for t, p in zip(y_true, y_pred) if t and not p)

        tpr = tp / (tp + fn) if (tp + fn) else 0
        tnr = tn / (tn + fp) if (tn + fp) else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tpr
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        # Bootstrap F1 CI
        _, f1_lower, f1_upper = bootstrap_f1_ci(y_true, y_pred)

        # Clopper-Pearson TNR CI
        tnr_ci_result = clopper_pearson_ci(tn, tn + fp)

        self.metrics[name] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "tpr": tpr, "tnr": tnr, "f1": f1,
            "f1_ci_lower": f1_lower, "f1_ci_upper": f1_upper,
            "n_total": len(y_true),
        }
        self.tnr_ci[name] = tnr_ci_result

        # 存储预测结果用于后续 McNemar 检验
        self._y_pred_store = getattr(self, "_y_pred_store", {})
        self._y_pred_store[name] = y_pred
        self._y_true = y_true

    def compute_mcnemar_pairs(self):
        """计算所有基线对之间的 McNemar 检验"""
        store = getattr(self, "_y_pred_store", {})
        y_true = getattr(self, "_y_true", [])

        self.mcnemar_results = []
        names = self.baseline_names

        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                result = mcnemar_test(
                    y_true,
                    store[names[i]],
                    store[names[j]],
                    name_a=names[i],
                    name_b=names[j],
                )
                self.mcnemar_results.append(result)

    def print_report(self):
        """打印完整的统计报告"""
        print(f"\n{'='*80}")
        print("STATISTICAL ANALYSIS REPORT")
        print(f"{'='*80}")

        # 各基线指标
        print(f"\n{'Baseline':<16} {'TPR':>8} {'TNR':>8} {'F1':>8} "
              f"{'F1 95% CI':>18} {'TNR 95% CI':>22}")
        print("-" * 80)

        for name in self.baseline_names:
            m = self.metrics[name]
            tnr_ci = self.tnr_ci[name]
            f1_ci_str = f"[{m['f1_ci_lower']:.3f}, {m['f1_ci_upper']:.3f}]"
            tnr_ci_str = f"[{tnr_ci.ci_lower:.1%}, {tnr_ci.ci_upper:.1%}]"
            print(f"{name:<16} {m['tpr']:>7.1%} {m['tnr']:>7.1%} {m['f1']:>7.3f} "
                  f"{f1_ci_str:>18} {tnr_ci_str:>22}")

        print("-" * 80)

        # McNemar 检验结果
        self.compute_mcnemar_pairs()
        print(f"\nMcNemar Pairwise Tests (α=0.05):")
        print("-" * 80)
        for result in self.mcnemar_results:
            sig_mark = "*" if result.significant else " "
            print(f"  [{sig_mark}] {result.description}")

        print("-" * 80)
        print("* = statistically significant difference (p < 0.05)")
        print("Note: McNemar test assumes paired data (same samples for both methods).")

        # TNR 置信区间特别说明
        print(f"\nTNR Clopper-Pearson 95% Confidence Intervals:")
        for name in self.baseline_names:
            ci = self.tnr_ci[name]
            print(f"  {name}: {ci}")
        print("(Clopper-Pearson is conservative; coverage ≥ nominal level.)")
