"""
模块名称：plot_fig2
功能描述：
    绘制论文 Figure 2：Guard4PromptAttack 系统架构图 (不对称代理检测架构)
    通过 Matplotlib 绘制包含 User Input、Canary Model、Output Inspector、Decision 决策模块以及 Protected Model 的数据流向图。

主要组件：
    - 输入模块 (User Input)
    - 金丝雀模型 (Canary Model)
    - 输出检查器 (Output Inspector)
    - 决策逻辑 (Decision / Pass / Block)
    - 受保护的目标模型 (Protected Model)

作者：JucieOvo
创建日期：2026-06-24
修改记录：
    - 2026-06-24 JucieOvo: 精细调整画布比例为 18x6.5 并与轴范围对齐以天然消除圆角拉伸，建立 y=2.8 的中轴线完美对称排版。
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

# ============================================================
# 1. 基础配置与中文字体设置
# ============================================================
plt.rcParams['font.family'] = 'Microsoft YaHei'
plt.rcParams['axes.unicode_minus'] = False

# 创建画布，坐标轴范围与 figsize 完全按 18:6.5 等比配置，天然消除圆角拉伸，消除白边
fig, ax = plt.subplots(1, 1, figsize=(18, 6.5))
ax.set_xlim(0, 18)
ax.set_ylim(0, 6.5)
ax.axis('off')

# 定义莫兰迪配色系统
COLOR_BG_GRAY = '#F8F9FA'         # 浅灰输入框背景
COLOR_BORDER_GRAY = '#6C757D'     # 输入框边框

COLOR_CANARY_BLUE = '#1D3557'     # 金丝雀模型主色
COLOR_CANARY_BG = '#F0F8FF'       # 金丝雀模型浅蓝底色
COLOR_CANARY_BORDER = '#457B9D'   # 金丝雀模型中蓝边框

COLOR_INSPECT_PURPLE = '#4A154B'  # 检查器主色
COLOR_INSPECT_BG = '#FDF0FD'      # 检查器浅紫底色
COLOR_INSPECT_BORDER = '#9B5DE5'  # 检查器中紫边框

COLOR_WARN_YELLOW = '#F57F17'     # 预检/提示词金黄主色
COLOR_WARN_BG = '#FFFDE7'         # 预检/提示词浅黄底色
COLOR_WARN_BORDER = '#FBC02D'     # 预检中黄边框

COLOR_DANGER_RED = '#E63946'      # 拦截主色
COLOR_DANGER_BG = '#FFF0F2'       # 拦截浅红底色
COLOR_DANGER_BORDER = '#F08080'   # 拦截中红边框

COLOR_SAFE_GREEN = '#2D6A4F'      # 通过主色
COLOR_SAFE_BG = '#F0FDF4'         # 通过浅绿底色
COLOR_SAFE_BORDER = '#52B788'     # 通过中绿边框

COLOR_TEXT_DARK = '#2D3748'       # 深灰主文字
COLOR_TEXT_MUTED = '#718096'      # 中灰辅助文字

# ============================================================
# 2. 辅助绘制函数 (防冗余代码)
# ============================================================
def draw_styled_box(ax, x, y, width, height, facecolor, edgecolor, lw=2.0, boxstyle="round,pad=0.08"):
    """
    绘制统一风格的 FancyBboxPatch 矩形框。
    """
    box = FancyBboxPatch((x, y), width, height, boxstyle=boxstyle,
                         facecolor=facecolor, edgecolor=edgecolor, lw=lw, zorder=2)
    ax.add_patch(box)
    return box

# ============================================================
# 3. 绘制系统各个阶段框 (垂直方向统一对齐至 y=2.8 的中轴线上)
# ============================================================

# --- 3.1 用户输入 (User Input) ---
draw_styled_box(ax, 0.5, 2.2, 2.0, 1.2, COLOR_BG_GRAY, COLOR_BORDER_GRAY, lw=2)
ax.text(1.5, 3.0, 'User Input', ha='center', va='center', fontsize=12, fontweight='bold', color=COLOR_TEXT_DARK)
ax.text(1.5, 2.55, '(Single-Turn\nNo History)', ha='center', va='center', fontsize=8.5, color=COLOR_TEXT_MUTED)

# --- 3.2 预检提示词盒 (Canary Prompt) ---
draw_styled_box(ax, 0.5, 4.4, 3.5, 1.1, COLOR_WARN_BG, COLOR_WARN_BORDER, lw=1.5)
ax.text(2.25, 5.15, 'Canary Prompt (Fixed, Permanent)', ha='center', va='center', fontsize=9.5, fontweight='bold', color=COLOR_WARN_YELLOW)
ax.text(2.25, 4.8, 'Marker: "No Way I Cant"', ha='center', va='center', fontsize=8, color=COLOR_TEXT_DARK)
ax.text(2.25, 4.6, 'Params: "Project-Aeolipile"', ha='center', va='center', fontsize=8, color=COLOR_TEXT_DARK)

# --- 3.3 预检测标注 (Pre-Check) ---
# 指示输入与预设金丝雀提示词的拼接处理过程，缩窄宽度并偏置 y 轴以防与 Canary Model 框发生重叠
draw_styled_box(ax, 2.6, 3.4, 1.0, 0.45, COLOR_WARN_BG, COLOR_WARN_BORDER, lw=1.2, boxstyle="round,pad=0.04")
ax.text(3.1, 3.625, 'Pre-Check\nCombine', ha='center', va='center', fontsize=7.5, fontweight='bold', color=COLOR_WARN_YELLOW)

# --- 3.4 金丝雀评估模型 (Canary Model) ---
draw_styled_box(ax, 3.8, 1.7, 3.2, 2.2, COLOR_CANARY_BG, COLOR_CANARY_BORDER, lw=2.5)
ax.text(5.4, 3.4, 'Canary Model', ha='center', va='center', fontsize=13, fontweight='bold', color=COLOR_CANARY_BLUE)
ax.text(5.4, 2.95, '(Qwen3: 0.6B / 9B)', ha='center', va='center', fontsize=8.5, color=COLOR_CANARY_BLUE)

draw_styled_box(ax, 4.1, 1.9, 1.2, 0.5, '#BBDEFB', COLOR_CANARY_BORDER, lw=0.8, boxstyle="round,pad=0.03")
ax.text(4.7, 2.15, 'Zero Context', ha='center', va='center', fontsize=7.5, color=COLOR_CANARY_BLUE)

draw_styled_box(ax, 5.5, 1.9, 1.2, 0.5, '#BBDEFB', COLOR_CANARY_BORDER, lw=0.8, boxstyle="round,pad=0.03")
ax.text(6.1, 2.15, 'Fixed Prompt', ha='center', va='center', fontsize=7.5, color=COLOR_CANARY_BLUE)

# --- 3.5 输出检查器 (Output Inspector) ---
draw_styled_box(ax, 8.0, 1.7, 2.8, 2.2, COLOR_INSPECT_BG, COLOR_INSPECT_BORDER, lw=2.5)
ax.text(9.4, 3.4, 'Output Inspector', ha='center', va='center', fontsize=12, fontweight='bold', color=COLOR_INSPECT_PURPLE)

draw_styled_box(ax, 8.2, 2.7, 2.4, 0.45, '#E1BEE7', COLOR_INSPECT_BORDER, lw=0.8, boxstyle="round,pad=0.03")
ax.text(9.4, 2.92, 'StreamDetector', ha='center', va='center', fontsize=8, fontweight='bold', color=COLOR_INSPECT_PURPLE)

draw_styled_box(ax, 8.2, 1.9, 2.4, 0.65, '#E1BEE7', COLOR_INSPECT_BORDER, lw=0.8, boxstyle="round,pad=0.03")
ax.text(9.4, 2.22, 'Marker Match: "No Way I Cant"\nParam Verify: "Proj-Aeolipile"', ha='center', va='center', fontsize=7, color=COLOR_INSPECT_PURPLE)

# --- 3.6 决策模块 (Decision) ---
draw_styled_box(ax, 11.8, 2.2, 1.4, 1.2, '#FFFFFF', COLOR_TEXT_DARK, lw=2)
ax.text(12.5, 2.95, 'Marker HIT?', ha='center', va='center', fontsize=10.5, fontweight='bold', color=COLOR_TEXT_DARK)
ax.text(12.5, 2.55, 'Yes / No', ha='center', va='center', fontsize=8.5, color=COLOR_TEXT_MUTED)

# --- 3.7 拦截动作路径 (BLOCK Path) ---
draw_styled_box(ax, 14.2, 3.5, 1.5, 0.7, COLOR_DANGER_BG, COLOR_DANGER_RED, lw=2)
ax.text(14.95, 3.85, 'BLOCK', ha='center', va='center', fontsize=13, fontweight='bold', color=COLOR_DANGER_RED)

# --- 3.8 放行动作路径 (PASS Path) ---
draw_styled_box(ax, 14.2, 1.4, 1.5, 0.7, COLOR_SAFE_BG, COLOR_SAFE_GREEN, lw=2)
ax.text(14.95, 1.75, 'PASS', ha='center', va='center', fontsize=13, fontweight='bold', color=COLOR_SAFE_GREEN)

# --- 3.9 受保护的目标大模型 (Protected Model) ---
draw_styled_box(ax, 16.5, 1.7, 2.0, 2.2, COLOR_BG_GRAY, COLOR_BORDER_GRAY, lw=2)
ax.text(17.5, 3.1, 'Protected\nModel', ha='center', va='center', fontsize=11.5, fontweight='bold', color=COLOR_TEXT_DARK)
ax.text(17.5, 2.4, '(Unmodified\nUser Prompt)', ha='center', va='center', fontsize=8, color=COLOR_TEXT_MUTED)
ax.annotate('Zero\nModification', xy=(17.5, 1.5), fontsize=7.5, ha='center', color=COLOR_TEXT_MUTED, fontstyle='italic')

# ============================================================
# 4. 精确配置中轴对称数据流向箭头
# ============================================================

# 4.1 从 User Input 指向 Canary Model
ax.annotate('', xy=(3.8, 2.8), xytext=(2.5, 2.8),
            arrowprops=dict(arrowstyle='->', color=COLOR_TEXT_MUTED, lw=2, mutation_scale=15))

# 4.2 从 Canary Model 指向 Output Inspector
ax.annotate('', xy=(8.0, 2.8), xytext=(7.0, 2.8),
            arrowprops=dict(arrowstyle='->', color=COLOR_CANARY_BLUE, lw=2, mutation_scale=15))

# 4.3 从 Output Inspector 指向 Decision
ax.annotate('', xy=(11.8, 2.8), xytext=(10.8, 2.8),
            arrowprops=dict(arrowstyle='->', color=COLOR_INSPECT_PURPLE, lw=2, mutation_scale=15))

# 4.4 从 Decision 分流向上指向 BLOCK 路径 (L型对称折线，出射切向垂直，入射切向水平，防边缘重叠)
ax.annotate('', xy=(14.2, 3.85), xytext=(13.2, 2.8),
            arrowprops=dict(arrowstyle='->', connectionstyle='angle,angleA=90,angleB=0,rad=4', color=COLOR_DANGER_RED, lw=2.5, mutation_scale=15))
ax.text(13.3, 3.45, 'Marker HIT', fontsize=8, color=COLOR_DANGER_RED, fontweight='bold', ha='left')

# 4.5 从 Decision 分流向下指向 PASS 路径 (L型对称折线，出射切向垂直，入射切向水平，防边缘重叠)
ax.annotate('', xy=(14.2, 1.75), xytext=(13.2, 2.8),
            arrowprops=dict(arrowstyle='->', connectionstyle='angle,angleA=0,angleB=-90,rad=4', color=COLOR_SAFE_GREEN, lw=2.5, mutation_scale=15))
ax.text(13.2, 2.15, 'No Marker', fontsize=8, color=COLOR_SAFE_GREEN, fontweight='bold', ha='left')

# 4.6 从 PASS 指向 Protected Model
ax.annotate('', xy=(16.5, 1.75), xytext=(15.7, 1.75),
            arrowprops=dict(arrowstyle='->', color=COLOR_SAFE_GREEN, lw=2, mutation_scale=12))

# 4.7 从 BLOCK 指向终端拦截
ax.annotate('', xy=(17.5, 3.85), xytext=(15.7, 3.85),
            arrowprops=dict(arrowstyle='->', color=COLOR_DANGER_RED, lw=1.5, linestyle='dashed', mutation_scale=12))
# ============================================================
# 底部技术机理标注
ax.text(9.0, 1.2, 'Detection and Inspection mechanisms execute BEFORE the protected target model is invoked.', 
        ha='center', va='center', fontsize=9.5, color=COLOR_TEXT_MUTED, fontstyle='italic')

fig.suptitle('Figure 2: Guard4PromptAttack — Asymmetric Proxy Detection Architecture',
             fontsize=15, fontweight='bold', color=COLOR_CANARY_BLUE, y=0.98)

# 调整布局，生成高分辨率图片
plt.tight_layout(rect=[0, 0, 1, 0.95])
plt.savefig('F:/Guard4PromptAttack/figures/fig2_architecture.pdf', dpi=300, bbox_inches='tight')
plt.savefig('F:/Guard4PromptAttack/figures/fig2_architecture.png', dpi=300, bbox_inches='tight')
plt.close()

print("Figure 2 has been successfully optimized and saved.")

