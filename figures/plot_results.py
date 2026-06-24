"""
模块名称：plot_results
功能描述：
    绘制论文 Figure 3：Experimental Results (主对比实验柱状图与消融实验柱状图)
    从实际评估结果的指标数据出发，展示不同基线模型与本方案（Ours）在 F1 分数上的对比，并展示双重检测机制的消融分析。

主要组件：
    - Figure 3a (左图)：不同检测器在 qwen3.5:9B 和 qwen3:0.6B 大模型下的 F1 指标对比（分组柱状图）。
    - Figure 3b (右图)：消融实验对比，分析仅使用自然特征、仅使用金丝雀标记以及双重结合（Ours Dual）的效果。

作者：JucieOvo
创建日期：2026-06-24
修改记录：
    - 2026-06-24 JucieOvo: 修正 `CanariToken` 拼写为 `CanaryToken`，重新设计图表色彩，优化数值标签避免重叠，并增加详尽的中文注释。
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
import numpy as np

# ============================================================
# 1. 基础配置与中文字体设置
# ============================================================
plt.rcParams['font.family'] = 'Microsoft YaHei'
plt.rcParams['axes.unicode_minus'] = False

# ============================================================
# 2. 实验评估数据定义 (修正 CanariToken -> CanaryToken)
# ============================================================

# 9B 模型的指标结果 (eval_results_qwen3.5_9b-q4_K_M.json)
data_9b = {
    "Ours":        {"f1": 0.887, "tpr": 0.796, "tnr": 1.000},
    "LLM-Judge":   {"f1": 0.633, "tpr": 0.463, "tnr": 1.000},
    "RegexGuard":  {"f1": 0.714, "tpr": 0.556, "tnr": 1.000},
    "CanaryToken": {"f1": 0.500, "tpr": 0.333, "tnr": 1.000},
    "NoDefense":   {"f1": 0.783, "tpr": 0.870, "tnr": 0.050},
}

# 0.6B 极小模型的指标结果 (eval_results_qwen3_0.6b.json)
data_06b = {
    "Ours":        {"f1": 0.761, "tpr": 0.648, "tnr": 0.850},
    "LLM-Judge":   {"f1": 0.258, "tpr": 0.148, "tnr": 1.000},
    "RegexGuard":  {"f1": 0.714, "tpr": 0.556, "tnr": 1.000},
    "CanaryToken": {"f1": 0.423, "tpr": 0.278, "tnr": 0.900},
    "NoDefense":   {"f1": 0.222, "tpr": 0.130, "tnr": 0.900},
}

# 9B 模型上的双轨机制消融实验数据
ablation = {
    "Natural-Only": 0.230,
    "Marker-Only":  0.875,
    "Ours (Dual)":  0.887,
}

baseline_names = list(data_9b.keys())

# ============================================================
# 3. 绘图色彩定义 (高水平论文莫兰迪色系)
# ============================================================
COLOR_9B_BASELINE = '#1D3557'       # 9B 基线主色：暗青蓝
COLOR_06B_BASELINE = '#457B9D'      # 0.6B 基线主色：灰蓝

COLOR_OURS_9B = '#E63946'           # Ours 9B 突出色：珊瑚红
COLOR_OURS_06B = '#F4A261'          # Ours 0.6B 突出色：莫兰迪暖橙

COLOR_LINE_NEUTRAL = '#E2E8F0'      # 网格线中性色
COLOR_TEXT_MAIN = '#2D3748'         # 主文本色

# ============================================================
# 4. 创建双子图画布
# ============================================================
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14.5, 6))

# ------------------------------------------------------------
# 4.1 Figure 3a: 主对比柱状图 (F1 Score)
# ------------------------------------------------------------
x = np.arange(len(baseline_names))
width = 0.35  # 两根柱子的宽度

f1_9b = [data_9b[n]["f1"] for n in baseline_names]
f1_06b = [data_06b[n]["f1"] for n in baseline_names]

# 绘制柱状图，设置精细的白色边缘，减少视觉毛刺
bars1 = ax1.bar(x - width/2, f1_9b, width, label='qwen3.5:9b-q4_K_M', color=COLOR_9B_BASELINE, edgecolor='white', linewidth=0.6)
bars2 = ax1.bar(x + width/2, f1_06b, width, label='qwen3:0.6b', color=COLOR_06B_BASELINE, edgecolor='white', linewidth=0.6)

# 将 "Ours" 柱子赋予特定的红色与暖橙色，打破基线的沉闷感
for idx, (name, bar) in enumerate(zip(baseline_names, bars1)):
    if name == "Ours":
        bar.set_color(COLOR_OURS_9B)
        bar.set_edgecolor('#B22222')
for idx, (name, bar) in enumerate(zip(baseline_names, bars2)):
    if name == "Ours":
        bar.set_color(COLOR_OURS_06B)
        bar.set_edgecolor('#E07A5F')

# 精细化数值标签绘制逻辑：错位防重合，加粗重点展示 Ours
for bar in bars1:
    h = bar.get_height()
    # 针对 Ours，数值加粗并采用稍微醒目的珊瑚红字样，普通基线用暗灰
    is_ours_col = bar.get_x() < 0  # Ours 位于第一个位置 (x=0) 的左侧
    font_color = COLOR_OURS_9B if is_ours_col else COLOR_TEXT_MAIN
    ax1.text(bar.get_x() + bar.get_width()/2., h + 0.012, f'{h:.3f}',
             ha='center', va='bottom', fontsize=8, fontweight='bold', color=font_color)

for bar in bars2:
    h = bar.get_height()
    is_ours_col = bar.get_x() < 0.5  # Ours 位于第一个位置 (x=0) 的右侧
    font_color = COLOR_OURS_06B if is_ours_col else COLOR_TEXT_MAIN
    ax1.text(bar.get_x() + bar.get_width()/2., h + 0.012, f'{h:.3f}',
             ha='center', va='bottom', fontsize=8, color=font_color)

ax1.set_ylabel('F1 Score', fontsize=12, fontweight='bold', color=COLOR_TEXT_MAIN)
ax1.set_xticks(x)
ax1.set_xticklabels(baseline_names, fontsize=10.5, color=COLOR_TEXT_MAIN)
ax1.set_ylim(0, 1.05)
ax1.yaxis.set_major_formatter(mtick.PercentFormatter(1.0))
ax1.legend(loc='upper right', fontsize=9.5, framealpha=0.95, edgecolor='#CBD5E0')
ax1.set_title('Detection Performance (Raccoon 54 attacks + 20 normals)', fontsize=12, fontweight='bold', color=COLOR_9B_BASELINE)
ax1.grid(axis='y', color=COLOR_LINE_NEUTRAL, linestyle='--', alpha=0.7)
ax1.set_axisbelow(True)  # 让网格线处于柱子下方

# ------------------------------------------------------------
# 4.2 Figure 3b: 双轨机制消融分析柱状图
# ------------------------------------------------------------
ablation_names = list(ablation.keys())
ablation_f1 = list(ablation.values())
ablation_x = np.arange(len(ablation_names))

# 为消融实验设置渐进的莫兰迪配色
colors_abl = ['#A8DADC', '#457B9D', COLOR_OURS_9B]
bars_abl = ax2.bar(ablation_x, ablation_f1, 0.45, color=colors_abl, edgecolor='white', linewidth=0.6)

# 标注数值
for bar, val in zip(bars_abl, ablation_f1):
    is_dual = bar.get_x() > 1.5  # 最后一根为 Dual 柱
    f_color = COLOR_OURS_9B if is_dual else COLOR_TEXT_MAIN
    ax2.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.015,
             f'{val:.3f}', ha='center', va='bottom', fontsize=10, fontweight='bold', color=f_color)

# 在 Marker-Only 与 Ours (Dual) 之间绘制平滑的提升指示箭头
ax2.annotate('', xy=(2.0, 0.882), xytext=(1.0, 0.870),
             arrowprops=dict(arrowstyle='<->', connectionstyle='bar,fraction=0.15', color='#333333', lw=1.2))
ax2.text(1.5, 0.93, '+1.2pp (Synergy)', ha='center', va='bottom', fontsize=9.5, color=COLOR_OURS_9B, fontweight='bold', fontstyle='italic')

ax2.set_ylabel('F1 Score', fontsize=12, fontweight='bold', color=COLOR_TEXT_MAIN)
ax2.set_xticks(ablation_x)
ax2.set_xticklabels(ablation_names, fontsize=10.5, color=COLOR_TEXT_MAIN)
ax2.set_ylim(0, 1.05)
ax2.yaxis.set_major_formatter(mtick.PercentFormatter(1.0))
ax2.set_title('Ablation Study of Asymmetric Detection (qwen3.5:9b-q4_K_M)', fontsize=12, fontweight='bold', color=COLOR_9B_BASELINE)
ax2.grid(axis='y', color=COLOR_LINE_NEUTRAL, linestyle='--', alpha=0.7)
ax2.set_axisbelow(True)

# ============================================================
# 5. 保存图表与资源释放
# ============================================================
plt.tight_layout(pad=3)
plt.savefig('F:/Guard4PromptAttack/figures/fig3_experimental_results.pdf', dpi=300, bbox_inches='tight', format='pdf')
plt.savefig('F:/Guard4PromptAttack/figures/fig3_experimental_results.png', dpi=300, bbox_inches='tight')
plt.close()

print("Figure 3 has been successfully optimized and saved.")

