"""
components/certificate_card.py — Person 3b: Reasoning certificate UI

Consumes the exact shape generate_certificate() returns:
    {"summary": str, "context": str, "reasons": [{"phrase", "impact_level"}]}
combined with the prediction result (attack_type, confidence, is_attack).
"""

from html import escape

import streamlit as st

COLORS = {
    'DDoS': '#E53935', 'PortScan': '#F57C00', 'Bot': '#8E24AA',
    'Web Attack': '#FBC02D', 'Infiltration': '#6D4C41',
    'Brute Force': '#F57C00', 'DoS': '#C62828', 'BENIGN': '#43A047',
}

IMPACT_BADGE = {
    'high': '🔴 High impact',
    'moderate': '🟡 Moderate impact',
}


def render_certificate_card(attack_type: str, confidence: float, certificate: dict):
    """
    attack_type / confidence: from the prediction result (IDSExplainer.predict()).
    certificate: the dict returned by certificate_generator.generate_certificate(),
                 i.e. {"summary": str, "context": str, "reasons": [...]}
    """
    color = COLORS.get(attack_type, '#9E9E9E')
    is_benign = attack_type == 'BENIGN'
    gradient = ("linear-gradient(135deg,#1b5e20,#2e7d32)" if is_benign
                else f"linear-gradient(135deg, {color}dd, {color}aa)")

    reasons_html = "".join(
        f"<li>{escape(str(r.get('phrase', '')))} <span style='opacity:0.75;font-size:11px;'>"
        f"({escape(IMPACT_BADGE.get(r.get('impact_level'), str(r.get('impact_level', ''))))})</span></li>"
        for r in certificate.get('reasons', [])
    )

    st.markdown(f"""
    <div style="background:{gradient}; color:white; padding:20px; border-radius:8px;
                border-left:5px solid {color};">
        <h3 style="margin:0 0 12px 0;">{'✅' if is_benign else '🚨'} {escape(attack_type.upper())}</h3>

        <div style="font-size:12px; opacity:0.9;">Confidence</div>
        <div style="font-size:20px; font-weight:bold;">{confidence:.1f}%</div>
        <div style="background:rgba(255,255,255,0.3); border-radius:4px; height:8px; margin-top:6px;">
            <div style="background:white; height:100%; width:{confidence}%; border-radius:4px;"></div>
        </div>

        <hr style="margin:12px 0; border-top:1px solid rgba(255,255,255,0.3);">
        <div style="font-weight:bold; font-size:13px; margin-bottom:6px;">Reasoning Certificate</div>
        <p style="font-size:13px; line-height:1.6;">{escape(str(certificate.get('summary', 'No summary available.')))}</p>

        {"<ul style='font-size:12px; line-height:1.8; padding-left:18px;'>" + reasons_html + "</ul>" if reasons_html else ""}

        <hr style="margin:12px 0; border-top:1px solid rgba(255,255,255,0.3);">
        <div style="font-weight:bold; font-size:13px; margin-bottom:6px;">What does this mean?</div>
        <p style="font-size:13px; line-height:1.6;">{escape(str(certificate.get('context', 'No additional context available.')))}</p>
    </div>
    """, unsafe_allow_html=True)
