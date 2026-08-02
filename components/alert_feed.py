"""
components/alert_feed.py — Person 4: Live alert feed panel

Renders the alert list returned by database.get_alerts() — same shape
used by api/main.py's GET /alerts endpoint.
"""

import streamlit as st

ICONS = {
    'DDoS': '🚨', 'PortScan': '⚠️', 'Bot': '🤖', 'Web Attack': '🟡',
    'Infiltration': '🕵️', 'Brute Force': '⚠️', 'DoS': '🚨', 'BENIGN': '🟢',
}

COLORS = {
    'DDoS': '#E53935', 'PortScan': '#F57C00', 'Bot': '#8E24AA',
    'Web Attack': '#FBC02D', 'Infiltration': '#6D4C41',
    'Brute Force': '#F57C00', 'DoS': '#C62828', 'BENIGN': '#43A047',
}


def render_alert_feed(alerts: list, selected_id=None) -> int | None:
    """
    alerts: list of dicts as returned by database.get_alerts(), e.g.
        {"id", "timestamp", "attack_type", "confidence", "is_attack", "summary", "top_shap_values"}

    Returns the id of the alert the user clicked this run, or None.
    """
    if not alerts:
        st.info("No alerts yet. Run a prediction to populate the feed.")
        return None

    clicked_id = None
    for alert in alerts:
        attack_type = alert.get('attack_type', 'UNKNOWN')
        confidence = alert.get('confidence', 0)
        icon = ICONS.get(attack_type, '🔵')
        color = COLORS.get(attack_type, '#9E9E9E')
        is_selected = alert.get('id') == selected_id

        label = f"{icon} {attack_type} — {confidence:.1f}%  ·  #{alert.get('id')}"
        button_type = "primary" if is_selected else "secondary"

        if st.button(label, key=f"alert-{alert.get('id')}", use_container_width=True, type=button_type):
            clicked_id = alert.get('id')

        st.caption(f"{alert.get('timestamp', '')}")

    return clicked_id
