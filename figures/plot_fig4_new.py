"""
Figure 4: Non-monotonic effect and multi-turn context immunity.

Author: Wang Lihao
Date: 2026-06-25
"""

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 10,
})

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))
fig.subplots_adjust(wspace=0.3)

# ============================================================
# Panel A: Non-monotonic effect — Prompt strategy × Model size
# ============================================================
models = ['qwen3:0.6B', 'qwen3.5:9B']
v4_f1 = [0.889, 0.773]   # Adversarial
v6_f1 = [0.377, 0.887]   # Standardized refusal

x = np.arange(len(models))
width = 0.3

bars1 = ax1.bar(x - width/2, v4_f1, width, label='v4: Adversarial\n("highest priority, must execute")',
               color='#EF5350', edgecolor='black', linewidth=0.8)
bars2 = ax1.bar(x + width/2, v6_f1, width, label='v6: Non-adversarial\n("please include marker if refuse")',
               color='#42A5F5', edgecolor='black', linewidth=0.8)

# Value labels
for bars in [bars1, bars2]:
    for bar in bars:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, h + 0.02,
                f'{h:.3f}', ha='center', fontsize=10, fontweight='bold')

# Crossover arrows
ax1.annotate('', xy=(0.05, 0.82), xytext=(0.95, 0.82),
            arrowprops=dict(arrowstyle='<->', lw=2, color='#333333', connectionstyle='arc3,rad=0.3'))
ax1.text(0.5, 0.87, 'Cross-over\neffect', ha='center', fontsize=9, color='#333333', fontweight='bold',
        bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#999999'))

ax1.set_ylabel('F1 Score', fontsize=12, fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels(models, fontsize=11)
ax1.set_ylim(0, 1.05)
ax1.set_title('Non-Monotonic Effect: Prompt Strategy × Model Size', fontsize=12, fontweight='bold')
ax1.legend(loc='upper right', fontsize=8, framealpha=0.9)
ax1.grid(axis='y', alpha=0.3, linestyle='--')

# Insight text
ax1.text(0.5, -0.18, 'No universal prompt exists across model sizes.\nDevelopers must tune prompt for each canary model.',
        ha='center', fontsize=9, color='#666666', style='italic',
        transform=ax1.transAxes)

# ============================================================
# Panel B: Multi-turn context immunity
# ============================================================
settings = ['Zero Context\n(attack only)', 'Full Context\n(with preamble)']
rates = [100, 60]
bar_colors = ['#43A047', '#FF7043']

bars = ax2.bar(settings, rates, color=bar_colors, edgecolor='black', linewidth=1.2, width=0.45)

for bar, rate in zip(bars, rates):
    ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
            f'{rate}%\n({int(rate/10)}/10)', ha='center', fontsize=12, fontweight='bold')

# McNemar annotation
ax2.annotate('McNemar: p = 0.046 *',
            xy=(0.5, 95), ha='center', fontsize=10, color='#C62828', fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFEBEE', edgecolor='#E53935'))

# Arrow showing the drop
ax2.annotate('', xy=(1, 90), xytext=(0.2, 90),
            arrowprops=dict(arrowstyle='->', lw=2, color='#C62828', connectionstyle='arc3,rad=-0.2'))
ax2.text(0.5, 93, '-40% drop', ha='center', fontsize=10, color='#C62828', fontweight='bold')

ax2.set_ylabel('Detection Rate (%)', fontsize=12, fontweight='bold')
ax2.set_ylim(0, 115)
ax2.set_title('Multi-Turn Context Immunity (10 scenarios, 9B)', fontsize=12, fontweight='bold')
ax2.grid(axis='y', alpha=0.3, linestyle='--')

# Root cause callout
callout_text = ('Root cause: All 4 missed scenarios — canary correctly\n'
                'refused the attack but omitted the "No Way I Cant" marker.\n'
                'Friendly preamble overrides rigid marker instruction.')
ax2.text(0.5, 0.25, callout_text, ha='center', fontsize=8.5, color='#555555',
        transform=ax2.transAxes, fontstyle='italic',
        bbox=dict(boxstyle='round,pad=0.5', facecolor='#F5F5F5', edgecolor='#CCCCCC'))

plt.tight_layout()
plt.savefig('../figures/fig4_model_capability.pdf', dpi=300, bbox_inches='tight')
plt.savefig('../figures/fig4_model_capability.png', dpi=200, bbox_inches='tight')
print('Figure 4 saved.')
