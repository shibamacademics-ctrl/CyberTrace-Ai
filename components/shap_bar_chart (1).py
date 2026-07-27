"""
components/shap_bar_chart.py — Person 3a: SHAP bar chart visualization

Consumes the exact `top_shap_values` shape returned by api/main.py's
/predict endpoint:
    [{"feature": str, "shap_value": float, "impact": "positive"|"negative"}, ...]
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import streamlit as st


def render_shap_bar_chart(top_shap_values: list):
    """
    top_shap_values: list of dicts as returned by IDSExplainer.explain(),
                      e.g. via api/main.py's PredictResponse.top_shap_values
    """
    if not top_shap_values:
        st.info("No SHAP values to display.")
        return

    sorted_shap = sorted(top_shap_values, key=lambda x: abs(x['shap_value']), reverse=True)
    features = [s['feature'] for s in sorted_shap]
    values = [s['shap_value'] for s in sorted_shap]
    colors = ['#E84040' if v > 0 else '#2196F3' for v in values]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(features, values, color=colors)
    ax.set_xlabel('SHAP value (impact on prediction)')
    ax.set_title('Top Features Contributing to This Decision', fontweight='bold')
    ax.axvline(x=0, color='black', linewidth=0.8)
    ax.invert_yaxis()

    for i, v in enumerate(values):
        ax.text(v, i, f' {v:+.4f}', va='center', fontsize=8)

    plt.tight_layout()
    st.pyplot(fig)
    plt.close(fig)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("🔴 **Positive** — pushes toward the predicted attack type")
    with col2:
        st.markdown("🔵 **Negative** — pushes toward normal/other classes")
