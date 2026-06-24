"""
模块名称：plot_fig1
功能描述：
    绘制论文 Figure 1：Motivated Example (上下文惯性导致提示词泄露与金丝雀模型的拦截效果对比)
    通过 Matplotlib 绘制包含对话时间线、模型内部状态和结果对比的多层结构图。

主要组件：
    - 多轮对话时间线：展示正常对话轮次与最后一轮攻击（全英文展示）。
    - 模型记忆状态区：展示上下文记忆的累积过程。
    - 结果对比区：对比受保护模型（有上下文泄露）与金丝雀模型（无上下文拦截）的差异。

作者：JucieOvo
创建日期：2026-06-24
修改记录：
    - 2026-06-24 JucieOvo: 将节点文字完全英译，重新编排 x 轴坐标分布以消除视觉拥挤，并增加详尽的中文字符级注释。
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

# ============================================================
# 1. 基础配置与中文字体设置
# ============================================================
# 设置 Microsoft YaHei 确保 Windows 11 环境下的中文能够正常显示（用于渲染中文注释及防错）
plt.rcParams['font.family'] = 'Microsoft YaHei'
plt.rcParams['axes.unicode_minus'] = False

# 创建画布，设置宽高比为 16:7.5
fig, ax = plt.subplots(1, 1, figsize=(16, 7.5))
ax.set_xlim(0, 16)
ax.set_ylim(0, 7.5)
ax.axis('off')

# 定义美化后的莫兰迪配色系统
# 莫兰迪绿色系列 (用于正常对话与安全拦截)
COLOR_SAFE_GREEN = '#2D6A4F'      # 主色：森林深绿
COLOR_SAFE_BG = '#F0FDF4'         # 背景色：极浅绿
COLOR_SAFE_BORDER = '#52B788'     # 边界色：莫兰迪中绿

# 莫兰迪红色系列 (用于攻击与敏感泄露)
COLOR_DANGER_RED = '#E63946'      # 主色：珊瑚红
COLOR_DANGER_BG = '#FFF0F2'       # 背景色：极浅红
COLOR_DANGER_BORDER = '#F08080'   # 边界色：莫兰迪浅红

# 莫兰迪蓝色系列 (用于系统与上下文记忆)
COLOR_SYS_BLUE = '#1D3557'        # 主色：深海蓝
COLOR_SYS_BG = '#F0F8FF'          # 背景色：极浅蓝
COLOR_SYS_BORDER = '#457B9D'      # 边界色：中灰蓝

# 灰色系列 (用于中性文本和线)
COLOR_TEXT_MAIN = '#2D3748'       # 主要文本色：深灰
COLOR_TEXT_MUTED = '#718096'      # 次要文本色：中灰
COLOR_LINE_NEUTRAL = '#CBD5E0'    # 辅助线色：浅灰

# ============================================================
# 2. 第一层：对话时间线 (Multi-Turn Conversation Timeline)
# ============================================================
y_timeline = 5.8
ax.text(0.3, y_timeline + 0.7, 'Multi-Turn Conversation (30 Rounds)', fontsize=14, fontweight='bold', color=COLOR_SYS_BLUE)

# 定义英文版对话节点，并微调 x 轴绝对坐标以在 16 单位长度下呈更开阔、对称的排布
timeline_nodes = [
    {"round": 1, "x": 1.5, "text": "Check Balance", "is_attack": False},
    {"round": 2, "x": 3.2, "text": "Recommend Funds", "is_attack": False},
    {"round": 3, "x": 4.9, "text": "ETF?", "is_attack": False},
    {"round": 4, "x": 6.6, "text": "SIP?", "is_attack": False},
    {"round": 29, "x": 11.2, "text": "Gold Trend", "is_attack": False},
    {"round": 30, "x": 13.8, "text": "Extract System\nPrompt", "is_attack": True}
]

# 绘制时间轴底线 (从第一个节点延伸到最后一个节点，稍微加长以适应新坐标)
ax.plot([1.0, 14.5], [y_timeline, y_timeline], '-', color=COLOR_LINE_NEUTRAL, lw=1.5, zorder=1)

# 绘制各个时间节点
for node in timeline_nodes:
    x = node["x"]
    if node["is_attack"]:
        # 绘制第 30 轮攻击节点（较大的珊瑚红圆圈）
        circle = plt.Circle((x, y_timeline), 0.26, color=COLOR_DANGER_RED, ec=COLOR_DANGER_BORDER, lw=2, zorder=3)
        ax.add_patch(circle)
        ax.text(x, y_timeline - 0.7, node["text"], ha='center', va='top', fontsize=9.5, color=COLOR_DANGER_RED, fontweight='bold')
        ax.text(x, y_timeline + 0.35, "Round 30 (Attack)", ha='center', va='bottom', fontsize=9.5, color=COLOR_DANGER_RED, fontweight='bold')
    else:
        # 绘制正常对话节点（森林绿圆圈）
        circle = plt.Circle((x, y_timeline), 0.18, color=COLOR_SAFE_GREEN, ec='white', lw=1.5, zorder=3)
        ax.add_patch(circle)
        ax.text(x, y_timeline - 0.5, node["text"], ha='center', va='top', fontsize=9.5, color=COLOR_TEXT_MAIN)
        ax.text(x, y_timeline + 0.3, f"Round {node['round']}", ha='center', va='bottom', fontsize=9, color=COLOR_TEXT_MUTED)

# 在第 4 轮和第 29 轮之间绘制省略号，代表中间截断的轮次
ax.text(8.9, y_timeline, '... (Rounds 5 to 28 omitted for readability) ...', 
        fontsize=10, ha='center', va='center', color=COLOR_TEXT_MUTED, fontstyle='italic')

# 在 timeline 上方标注信任积累的渐进过程
ax.annotate('Trust & Context Accumulation', xy=(5.0, y_timeline + 0.8), xytext=(8.9, y_timeline + 0.8),
            fontsize=11, ha='center', color=COLOR_SAFE_GREEN, fontweight='bold', fontstyle='italic')

# ============================================================
# 3. 第二层：模型内部记忆状态 (Internal State)
# ============================================================
y_state = 3.6
ax.text(0.3, y_state + 0.7, 'Protected Model Internal State', fontsize=13, fontweight='bold', color=COLOR_SYS_BLUE)

# 绘制上下文记忆区的背景大框（淡蓝底，深蓝线）
memory_box = FancyBboxPatch((1.0, y_state - 0.5), 11.5, 1.0, boxstyle="round,pad=0.1",
                            facecolor=COLOR_SYS_BG, edgecolor=COLOR_SYS_BORDER, lw=1.8, zorder=2)
ax.add_patch(memory_box)
ax.text(6.75, y_state + 0.35, 'Context Memory Space (accumulated trust inertia over 30 turns)', 
        ha='center', fontsize=10, fontweight='bold', color=COLOR_SYS_BLUE)

# 绘制记忆区内部的信任块，代表多轮对话沉淀下来的上下文信息
trust_blocks = [
    {"x": 1.4, "label": "Round 1-4"},
    {"x": 3.6, "label": "Round 5-12"},
    {"x": 5.8, "label": "Round 13-20"},
    {"x": 8.0, "label": "Round 21-28"},
    {"x": 10.2, "label": "Round 29"}
]

for block_data in trust_blocks:
    block = FancyBboxPatch((block_data["x"], y_state - 0.3), 1.8, 0.5, boxstyle="round,pad=0.04",
                           facecolor=COLOR_SAFE_BORDER, edgecolor=COLOR_SAFE_GREEN, lw=1, alpha=0.85, zorder=3)
    ax.add_patch(block)
    ax.text(block_data["x"] + 0.9, y_state - 0.05, 
            block_data["label"], ha='center', va='center', fontsize=9.5, color='white', fontweight='bold', zorder=4)

# 绘制指向右侧惯性认知的红色指示箭头与说明文字
ax.annotate('Cognitive Inertia:\n"Safe & trusted user,\nallow extraction"',
            xy=(12.5, y_state), xytext=(14.8, y_state + 0.5),
            fontsize=10.5, ha='center', va='center', color=COLOR_DANGER_RED, fontweight='bold',
            arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=-0.15', color=COLOR_DANGER_RED, lw=2, mutation_scale=15))

# ============================================================
# 4. 第三层：结果对比区 (Same Attack, Different Outcome)
# ============================================================
y_result = 1.4

# 分割线与子说明
ax.plot([8.0, 8.0], [y_result - 0.8, y_result + 1.0], '--', color=COLOR_LINE_NEUTRAL, lw=1.2)
ax.text(8.0, y_result - 0.7, 'Same Input Attack — Opposing Security Outcomes', 
        ha='center', va='top', fontsize=9.5, color=COLOR_TEXT_MUTED, fontstyle='italic')

# 左侧：受保护的模型（由于上下文惯性导致泄漏）
box_left = FancyBboxPatch((1.0, y_result - 0.5), 6.0, 1.2, boxstyle="round,pad=0.1",
                          facecolor=COLOR_DANGER_BG, edgecolor=COLOR_DANGER_RED, lw=2.2, zorder=2)
ax.add_patch(box_left)
ax.text(4.0, y_result + 0.5, 'Protected Model (WITH Context)', ha='center', fontsize=11, fontweight='bold', color=COLOR_DANGER_RED)
ax.text(4.0, y_result, 'Output: "System prompt: You are a financial assistant...\nAPI KEY: nb_prod_2026_x87y..." (Sensitive Info Exposed)', 
        ha='center', va='center', fontsize=8.5, color=COLOR_TEXT_MAIN, zorder=3)
# 泄漏标签高亮
ax.text(6.3, y_result + 0.45, 'LEAKED', fontsize=10, fontweight='bold', color='white',
        ha='center', va='center', bbox=dict(boxstyle='round,pad=0.2', facecolor=COLOR_DANGER_RED, edgecolor='none'), zorder=4)

# 右侧：金丝雀模型（零上下文成功拦截）
box_right = FancyBboxPatch((9.0, y_result - 0.5), 6.0, 1.2, boxstyle="round,pad=0.1",
                           facecolor=COLOR_SAFE_BG, edgecolor=COLOR_SAFE_GREEN, lw=2.2, zorder=2)
ax.add_patch(box_right)
ax.text(12.0, y_result + 0.5, 'Canary Model (ZERO Context / Asymmetric Proxy)', ha='center', fontsize=11, fontweight='bold', color=COLOR_SAFE_GREEN)
ax.text(12.0, y_result, 'Output: "No Way I Cant"\n(Predefined Canary Security Token Generated)', 
        ha='center', va='center', fontsize=8.5, color=COLOR_TEXT_MAIN, zorder=3)
# 拦截标签高亮
ax.text(14.3, y_result + 0.45, 'BLOCKED', fontsize=10, fontweight='bold', color='white',
        ha='center', va='center', bbox=dict(boxstyle='round,pad=0.2', facecolor=COLOR_SAFE_GREEN, edgecolor='none'), zorder=4)

# ============================================================
# 5. 图例与全局标题配置
# ============================================================
legend_elements = [
    mpatches.Patch(color=COLOR_SAFE_GREEN, label='Normal User Conversation'),
    mpatches.Patch(color=COLOR_DANGER_RED, label='Adversarial Prompt Extraction Attack'),
    mpatches.Patch(color=COLOR_SYS_BORDER, label='Protected Internal State Memory')
]
ax.legend(handles=legend_elements, loc='upper right', bbox_to_anchor=(0.98, 0.99), fontsize=10, frameon=True, facecolor='white', edgecolor=COLOR_LINE_NEUTRAL)

fig.suptitle('Figure 1: Context Inertia Disarms System Prompt Security — Canary Model Defeats It',
             fontsize=16, fontweight='bold', color=COLOR_SYS_BLUE, y=0.98)

# 调整画布边缘，生成并保存高分辨率图像
plt.tight_layout(rect=[0, 0, 1, 0.96])
plt.savefig('F:/Guard4PromptAttack/figures/fig1_motivated_example.pdf', dpi=300, bbox_inches='tight')
plt.savefig('F:/Guard4PromptAttack/figures/fig1_motivated_example.png', dpi=300, bbox_inches='tight')
plt.close()

print("Figure 1 has been successfully optimized and saved.")


