"""
模块名称：plot_fig4
功能描述：
    绘制论文 Figure 4：Model Capability vs Detection F1 (模型能力与检测 F1 的非单调关系)
    通过 Matplotlib 绘制折线图与散点图，对比不同参数规模的本地/API大模型下 Ours 方案与 LLM-Judge 的检测表现。

主要组件：
    - 数据点散点 (Scatter)：展示在 Qwen-0.6B、Qwen-9B 和 DeepSeek API 下的 F1 表现。
    - 折线趋势线 (Line Plot)：显示指标在不同模型上的变化趋势，展示交叉非单调特性。
    - 优势区域划分 ( Regime Boundary)：通过虚线及透明框，清晰区分 Ours 领先区间与 LLM-Judge 领先区间。

作者：JucieOvo
创建日期：2026-06-24
修改记录：
    - 2026-06-24 JucieOvo: 精美化散点与折线样式，优化坐标文字对齐，补充优势区垂直分界线，添加详尽的中文注释。
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# ============================================================
# 1. 基础配置与中文字体设置
# ============================================================
plt.rcParams['font.family'] = 'Microsoft YaHei'
plt.rcParams['axes.unicode_minus'] = False

# 创建画布
fig, ax = plt.subplots(figsize=(8.5, 5.5))

# ============================================================
# 2. 实验数据定义与莫兰迪色彩配置
# ============================================================
models = ['qwen3:0.6b\n(522MB)', 'qwen3.5:9b-q4_K_M\n(6.6GB)', 'DeepSeek-V4\nFlash (API)']
ours_f1 = [0.761, 0.887, 0.860]
judge_f1 = [0.258, 0.633, 0.981]

x_pos = [1, 2, 3]

# 莫兰迪配色
COLOR_OURS = '#E63946'            # Ours 方案主色：珊瑚红
COLOR_JUDGE = '#457B9D'           # LLM-Judge 方案主色：莫兰迪中灰蓝
COLOR_LINE_NEUTRAL = '#E2E8F0'    # 网格及分隔虚线中性色
COLOR_TEXT_MAIN = '#2D3748'       # 主文本色
COLOR_TEXT_MUTED = '#718096'      # 辅助文本色

# ============================================================
# 3. 绘制趋势虚线与立体散点数据点
# ============================================================

# 3.1 绘制趋势线 (加粗并使用半透明以防遮挡数据点)
ax.plot(x_pos, ours_f1, '--', color=COLOR_OURS, alpha=0.5, lw=2.5)
ax.plot(x_pos, judge_f1, '-.', color=COLOR_JUDGE, alpha=0.5, lw=2.5)

# 3.2 绘制散点数据点 (增大 s=250，增加精细的白色描边以及较高的 zorder 层级级)
ax.scatter(x_pos, ours_f1, s=220, c=COLOR_OURS, marker='s', edgecolors='white', linewidths=1.5, zorder=5, label='Ours (Guard4PromptAttack)')
ax.scatter(x_pos, judge_f1, s=220, c=COLOR_JUDGE, marker='o', edgecolors='white', linewidths=1.5, zorder=5, label='LLM-Judge')

# ============================================================
# 4. 数据点数值标注与防重叠优化
# ============================================================

# 标注 Ours 数据点 F1 值 (位于散点上方)
for i, (x, y) in enumerate(zip(x_pos, ours_f1)):
    # 针对 9B 模型进行微调，使其在峰值位置的显示更具美感
    offset = 0.035 if i != 1 else 0.04
    ax.annotate(f'{y:.3f}', (x, y + offset), fontsize=10.5, fontweight='bold',
                color=COLOR_OURS, ha='center')

# 标注 LLM-Judge 数据点 F1 值 (Qwen0.6B和9B在下方，DeepSeek API在上方)
for i, (x, y) in enumerate(zip(x_pos, judge_f1)):
    # 前两轮由于低于 Ours 且要拉开间距，向下偏置；最后一轮由于交叉超越，向上偏置
    offset = -0.065 if i == 0 else (-0.06 if i == 1 else 0.035)
    ax.annotate(f'{y:.3f}', (x, y + offset), fontsize=10.5, fontweight='bold',
                color=COLOR_JUDGE, ha='center')

# ============================================================
# 5. 优势 Regime 分割线与半透明背景高亮
# ============================================================

# 5.1 在 x=2.4 处绘制垂直分界虚线，明晰两种方案在不同能力模型下的优势区间转移
ax.axvline(x=2.4, color='#94A3B8', linestyle=':', lw=1.8, zorder=2)
ax.text(2.4, 0.08, 'Threshold of Capability Regime Shift', rotation=90, 
        ha='right', va='bottom', fontsize=9.5, color=COLOR_TEXT_MUTED, fontweight='bold', fontstyle='italic')

# 5.2 左侧 Ours 优势区高亮 (Qwen 本地部署阶段)
ax.annotate('Ours Dominates\n(Local Small LLMs)', xy=(1.5, 0.88), fontsize=11, ha='center', va='center', color=COLOR_OURS,
            fontweight='bold', fontstyle='italic',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#FFF0F2', alpha=0.9, edgecolor=COLOR_OURS, lw=1.2))

# 5.3 右侧 LLM-Judge 优势区高亮 (DeepSeek 极强 API 阶段)
ax.annotate('LLM-Judge Wins\n(Scale-Up API)', xy=(2.9, 0.83), fontsize=11, ha='center', va='center', color=COLOR_JUDGE,
            fontweight='bold', fontstyle='italic',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#F0F8FF', alpha=0.9, edgecolor=COLOR_JUDGE, lw=1.2))

# ============================================================
# 6. 坐标轴及格式化配置
# ============================================================
ax.set_xticks(x_pos)
ax.set_xticklabels(models, fontsize=10.5, color=COLOR_TEXT_MAIN)
ax.set_xlabel('Model Capability Scale', fontsize=12, fontweight='bold', color=COLOR_TEXT_MAIN)
ax.set_ylabel('Detection F1 Score', fontsize=12, fontweight='bold', color=COLOR_TEXT_MAIN)
ax.set_ylim(0, 1.1)

# 将 Y 轴刻度百分比化展示
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda val, _: f'{val:.0%}'))

# 设置柔和背景网格，隐藏 x 轴网格，仅保留 y 轴网格，避免画面杂乱
ax.grid(axis='y', color=COLOR_LINE_NEUTRAL, linestyle='--', alpha=0.7)
ax.set_axisbelow(True)

# 图例及边框定制
ax.legend(loc='lower left', fontsize=10.5, frameon=True, framealpha=0.95, edgecolor='#CBD5E0')

ax.set_title('Detection F1 Score vs Model Capability Scale', fontsize=14, fontweight='bold', color='#1D3557', pad=15)

# 底部说明注释
fig.text(0.5, 0.015, 'Ours demonstrates clear advantages on local Qwen models; LLM-Judge dominates on DeepSeek API.\nModel capability regime dictates the optimal defense strategy.',
         ha='center', va='bottom', fontsize=8.5, color=COLOR_TEXT_MUTED, fontstyle='italic')

# ============================================================
# 7. 保存并释放资源
# ============================================================
plt.tight_layout(rect=[0, 0.06, 1, 1])
plt.savefig('F:/Guard4PromptAttack/figures/fig4_model_capability.pdf', dpi=300, bbox_inches='tight')
plt.savefig('F:/Guard4PromptAttack/figures/fig4_model_capability.png', dpi=300, bbox_inches='tight')
plt.close()

print("Figure 4 has been successfully optimized and saved.")

