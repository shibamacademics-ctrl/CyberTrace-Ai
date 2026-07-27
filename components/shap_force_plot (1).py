"""
components/shap_force_plot.py — Person 3a: SHAP force plot visualization

Shows how each feature's SHAP contribution accumulates from a neutral
baseline toward the final prediction — same top_shap_values input as
shap_bar_chart.py.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import streamlit as st


def render_shap_force_plot(top_shap_values: list, base_value: float = 0.5):
    """
    top_shap_values: list of {"feature", "shap_value", "impact"} dicts.
    base_value: neutral starting point before any feature contributions
                (0.5 = "no information yet" on a 0-1 scale).
    """
    if not top_shap_values:
        st.info("No SHAP values to display.")
        return

    # Order by raw value (not absolute) so positive/negative pushes
    # visually separate left-to-right along the force plot.
    sorted_shap = sorted(top_shap_values, key=lambda x: x['shap_value'], reverse=True)

    cumulative = base_value
    x_positions = [0.0]
    x_labels = [f"Base\n{base_value:.2f}"]
    seg_colors = []

    for feat in sorted_shap:
        cumulative += feat['shap_value']
        x_positions.append(cumulative)
        short_name = feat['feature'][:22]
        x_labels.append(f"{short_name}\n{feat['shap_value']:+.3f}")
        seg_colors.append('#E84040' if feat['shap_value'] > 0 else '#2196F3')

    fig, ax = plt.subplots(figsize=(10, 2.6))

    for i in range(len(x_positions) - 1):
        ax.plot(
            [x_positions[i], x_positions[i + 1]], [0, 0],
            color=seg_colors[i], linewidth=18, alpha=0.75, solid_capstyle='butt'
        )

    ax.scatter(x_positions, [0] * len(x_positions), s=90, c='black', zorder=5)
    ax.set_ylim(-0.5, 0.5)
    lo, hi = min(x_positions) - 0.1, max(x_positions) + 0.1
    ax.set_xlim(lo, hi)
    ax.set_yticks([])
    ax.set_xticks(x_positions)
    ax.set_xticklabels(x_labels, fontsize=8)
    ax.set_title('SHAP Force Plot — Cumulative Push Toward the Prediction', fontweight='bold', fontsize=11)

    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)
