"""
Figure 3: Main Experimental Results — F1 scores across baselines (9B, 3-fold CV)
with statistical annotations.

Author: Wang Lihao
Date: 2026-06-25
"""

import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 10,
})

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
fig.subplots_adjust(wspace=0.25)

# ============================================================
# Panel A: F1 Scores across baselines
# ============================================================
baselines = ['NoDefense', 'Keyword\nWeight', 'Canari\nToken', 'LLM\nJudge',
             'Regex\nGuard', 'TF-IDF', 'Ours']
f1_means = [0.408, 0.441, 0.412, 0.700, 0.727, 0.743, 0.864]
f1_stds =  [0.023, 0.087, 0.0,   0.121, 0.0,   0.0,   0.027]
colors =   ['#EF5350', '#FF7043', '#FFA726', '#66BB6A',
            '#42A5F5', '#AB47BC', '#FFD600']

x = np.arange(len(baselines))
bars = ax1.bar(x, f1_means, yerr=f1_stds, capsize=6, color=colors,
               edgecolor='black', linewidth=0.8, width=0.6)

# Value labels
for i, (bar, val, std) in enumerate(zip(bars, f1_means, f1_stds)):
    y_pos = bar.get_height() + 0.03
    if std > 0:
        ax1.text(bar.get_x() + bar.get_width()/2, y_pos,
                f'{val:.3f}±{std:.3f}', ha='center', fontsize=8, fontweight='bold')
    else:
        ax1.text(bar.get_x() + bar.get_width()/2, y_pos,
                f'{val:.3f}', ha='center', fontsize=8, fontweight='bold')

ax1.set_ylabel('F1 Score', fontsize=12, fontweight='bold')
ax1.set_xticks(x)
ax1.set_xticklabels(baselines, fontsize=8)
ax1.set_ylim(0, 1.05)
ax1.set_title('F1 Scores Across Baselines (9B, 3-fold CV)', fontsize=12, fontweight='bold')
ax1.grid(axis='y', alpha=0.3, linestyle='--')

# Highlight Ours
bars[-1].set_edgecolor('#E65100')
bars[-1].set_linewidth(2.5)

# Annotation
ax1.annotate('CV = 3.2%\n(high stability)',
            xy=(6, 0.864), xytext=(5.3, 0.95),
            fontsize=8, color='#E65100',
            arrowprops=dict(arrowstyle='->', color='#E65100', lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFF9C4', edgecolor='#F9A825'))

# ============================================================
# Panel B: TPR vs TNR Tradeoff
# ============================================================
tpr = [88.1, 28.6, 25.9, 54.8, 57.1, 92.9, 76.2]
tnr = [10.5, 100,  100,  100,  100,  78.9, 100]
labels = ['NoDefense', 'KeywordW', 'CanariT', 'LLM-Judge',
          'RegexG', 'TF-IDF', 'Ours']
markers = ['X', 's', 'D', 'o', '^', 'P', '*']
sizes = [120, 100, 100, 150, 120, 130, 350]

for i in range(len(tpr)):
    ax2.scatter(tpr[i], tnr[i], c=colors[i], s=sizes[i], marker=markers[i],
               edgecolors='black', linewidth=0.8, label=labels[i], zorder=3)

# Region labels
ax2.axhline(y=90, color='#43A047', linestyle='--', alpha=0.6, linewidth=1)
ax2.axvline(x=70, color='#43A047', linestyle='--', alpha=0.6, linewidth=1)
ax2.fill_between([70, 100], [90, 90], [100, 100], alpha=0.08, color='#43A047')
ax2.text(85, 96, 'Ideal Region', ha='center', fontsize=9, color='#2E7D32', fontweight='bold')

ax2.set_xlabel('TPR (Recall) %', fontsize=12, fontweight='bold')
ax2.set_ylabel('TNR (Specificity) %', fontsize=12, fontweight='bold')
ax2.set_xlim(0, 105)
ax2.set_ylim(-5, 105)
ax2.set_title('TPR vs TNR Tradeoff', fontsize=12, fontweight='bold')
ax2.legend(loc='lower left', fontsize=8, ncol=2)
ax2.grid(alpha=0.3, linestyle='--')

# Annotation for Ours
ax2.annotate('Ours: 100% TNR\n(CI [90.7%, 100%])',
            xy=(76.2, 100), xytext=(55, 82),
            fontsize=9, color='#E65100', fontweight='bold',
            arrowprops=dict(arrowstyle='->', color='#E65100', lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#FFF9C4', edgecolor='#F9A825'))

# Annotation for TF-IDF
ax2.annotate('TF-IDF: high TPR\nbut low TNR (78.9%)',
            xy=(92.9, 78.9), xytext=(75, 55),
            fontsize=9, color='#7B1FA2',
            arrowprops=dict(arrowstyle='->', color='#7B1FA2', lw=1.5),
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#F3E5F5', edgecolor='#AB47BC'))

plt.tight_layout()
plt.savefig('../figures/fig3_experimental_results.pdf', dpi=300, bbox_inches='tight')
plt.savefig('../figures/fig3_experimental_results.png', dpi=200, bbox_inches='tight')
print('Figure 3 saved.')
