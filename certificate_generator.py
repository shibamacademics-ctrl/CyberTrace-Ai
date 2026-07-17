"""
certificate_generator.py
Turns SHAP feature contributions into a human-readable "Reasoning Certificate".
"""

ATTACK_CONTEXT = {
    "DDoS": "A DDoS attack floods the network with traffic to overwhelm a target and deny service to legitimate users.",
    "PortScan": "A port scan probes many ports on a host to discover open services and potential entry points.",
    "Brute Force": "A brute force attack repeatedly guesses credentials to gain unauthorized access.",
    "Web Attack": "A web attack targets application-layer vulnerabilities such as injection or XSS.",
    "Bot": "Bot traffic indicates a compromised host communicating with a command-and-control server.",
    "Infiltration": "Infiltration traffic indicates an attacker has already gained a foothold inside the network.",
    "DoS": "A DoS attack overwhelms a single target from one source to disrupt service.",
    "BENIGN": "This traffic pattern is consistent with normal, non-malicious network activity.",
}

FEATURE_PHRASES = {
    "Flow Duration": ("the flow lasted for an unusually long duration", "the flow ended unusually quickly"),
    "Total Fwd Packets": ("an unusually high number of forward packets were sent", "very few forward packets were sent"),
    "Total Backward Packets": ("an unusually high number of backward packets were sent", "very few backward packets were returned"),
    "Total Length of Fwd Packets": ("the total forward payload size was unusually large", "the total forward payload size was unusually small"),
    "Total Length of Bwd Packets": ("the total backward payload size was unusually large", "the total backward payload size was unusually small"),
    "Fwd Packet Length Max": ("the largest forward packet was unusually large", "the largest forward packet was unusually small"),
    "Fwd Packet Length Mean": ("forward packet sizes were unusually large on average", "forward packet sizes were unusually small on average"),
    "Fwd Packet Length Std": ("forward packet sizes varied unusually widely", "forward packet sizes were unusually uniform"),
    "Bwd Packet Length Max": ("the largest backward packet was unusually large", "the largest backward packet was unusually small"),
    "Bwd Packet Length Mean": ("backward packet sizes were unusually large on average", "backward packet sizes were unusually small on average"),
    "Bwd Packet Length Std": ("backward packet sizes varied unusually widely", "backward packet sizes were unusually uniform"),
    "Min Packet Length": ("the smallest packet in the flow was unusually large", "an unusually tiny packet appeared in the flow"),
    "Max Packet Length": ("the largest packet in the flow was unusually large", "the largest packet in the flow was unusually small"),
    "Packet Length Mean": ("average packet size was unusually large", "average packet size was unusually small"),
    "Packet Length Std": ("packet sizes varied unusually widely", "packet sizes varied unusually little"),
    "Packet Length Variance": ("packet size variance was unusually high", "packet sizes were unusually uniform"),
    "Average Packet Size": ("average packet size was unusually large", "average packet size was unusually small"),
    "Avg Fwd Segment Size": ("average forward segment size was unusually large", "average forward segment size was unusually small"),
    "Avg Bwd Segment Size": ("average backward segment size was unusually large", "average backward segment size was unusually small"),
    "Flow Bytes/s": ("byte throughput spiked abnormally", "byte throughput was abnormally low"),
    "Flow Packets/s": ("packet rate spiked abnormally", "packet rate was abnormally low"),
    "Fwd Packets/s": ("forward packet rate spiked abnormally", "forward packet rate was abnormally low"),
    "Bwd Packets/s": ("backward packet rate spiked abnormally", "backward packet rate was abnormally low"),
    "Flow IAT Mean": ("the average time between packets dropped sharply", "the average time between packets was unusually long"),
    "Flow IAT Std": ("packet timing varied unusually widely", "packet timing was unusually consistent"),
    "Flow IAT Max": ("an unusually long gap occurred between packets", "the longest gap between packets was unusually short"),
    "Flow IAT Min": ("packets arrived back-to-back with almost no gap", "the shortest gap between packets was unusually long"),
    "Fwd IAT Mean": ("forward packets arrived unusually close together", "forward packets arrived unusually far apart"),
    "Fwd IAT Std": ("forward packet timing varied unusually widely", "forward packet timing was unusually consistent"),
    "Fwd IAT Max": ("an unusually long gap occurred between forward packets", "the longest forward packet gap was unusually short"),
    "Fwd IAT Min": ("forward packets arrived back-to-back with almost no gap", "the shortest forward packet gap was unusually long"),
"Bwd IAT Max": ("an unusually long gap occurred between backward packets", "the longest backward packet gap was unusually short"),
    "Bwd IAT Min": ("backward packets arrived back-to-back with almost no gap", "the shortest backward packet gap was unusually long"),
    "FIN Flag Count": ("an unusual number of FIN (connection close) flags were observed", "fewer FIN flags than expected were observed"),
    "SYN Flag Count": ("an unusual number of SYN (connection request) flags were observed", "fewer SYN flags than expected were observed"),
    "RST Flag Count": ("an unusual number of RST (connection reset) flags were observed", "fewer RST flags than expected were observed"),
    "PSH Flag Count": ("an unusual number of PSH (push data) flags were observed", "fewer PSH flags than expected were observed"),
    "ACK Flag Count": ("an unusual number of ACK flags were observed", "fewer ACK flags than expected were observed"),
    "URG Flag Count": ("an unusual number of URG (urgent) flags were observed", "fewer URG flags than expected were observed"),
    "ECE Flag Count": ("an unusual number of ECE (congestion) flags were observed", "fewer ECE flags than expected were observed"),
    "Init_Win_bytes_forward": ("the forward initial TCP window size was unusually large", "the forward initial TCP window size was unusually small"),
    "Init_Win_bytes_backward": ("the backward initial TCP window size was unusually large", "the backward initial TCP window size was unusually small"),
    "Active Mean": ("the connection stayed active for unusually long stretches", "active periods were unusually short"),
    "Active Std": ("active period lengths varied unusually widely", "active period lengths were unusually consistent"),
    "Active Max": ("the longest active period was unusually long", "the longest active period was unusually short"),
    "Active Min": ("the shortest active period was unusually long", "the shortest active period was unusually brief"),
    "Idle Mean": ("the connection sat idle for unusually long stretches", "idle periods were unusually short"),
    "Idle Std": ("idle period lengths varied unusually widely", "idle period lengths were unusually consistent"),
    "Idle Max": ("the longest idle period was unusually long", "the longest idle period was unusually short"),
    "Idle Min": ("the shortest idle period was unusually long", "the shortest idle period was unusually brief"),
    "Subflow Fwd Packets": ("an unusually high number of forward packets per subflow", "an unusually low number of forward packets per subflow"),
    "Subflow Fwd Bytes": ("an unusually high number of forward bytes per subflow", "an unusually low number of forward bytes per subflow"),
    "Subflow Bwd Packets": ("an unusually high number of backward packets per subflow", "an unusually low number of backward packets per subflow"),
    "Subflow Bwd Bytes": ("an unusually high number of backward bytes per subflow", "an unusually low number of backward bytes per subflow"),
    "Down/Up Ratio": ("the download-to-upload ratio was unusually skewed", "the download-to-upload ratio was unusually balanced"),
}


def _phrase_for(feature: str, impact: str) -> str:
    if feature in FEATURE_PHRASES:
        positive_phrase, negative_phrase = FEATURE_PHRASES[feature]
        return positive_phrase if impact == "positive" else negative_phrase
    direction = "higher" if impact == "positive" else "lower"
    return f"'{feature}' was significantly {direction} than normal"
def generate_certificate(attack_type: str, confidence: float, top_shap_values: list) -> dict:
    """
    top_shap_values: list of {"feature", "shap_value", "impact"} dicts,
    as returned by IDSExplainer.explain().
    """
    driving = [f for f in top_shap_values if f["impact"] == "positive"] or top_shap_values

    reasons = []
    phrases = []
    for f in driving[:3]:
        phrase = _phrase_for(f["feature"], f["impact"])
        phrases.append(phrase)
        reasons.append({
            "phrase": phrase,
            "impact_level": "high" if abs(f["shap_value"]) > 0.3 else "moderate",
        })

    if attack_type == "BENIGN":
        summary = f"Classified as normal traffic (BENIGN) with {confidence:.1f}% confidence."
    elif phrases:
        joined = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + f", and {phrases[-1]}"
        summary = f"Flagged as {attack_type} because {joined}."
    else:
        summary = f"Flagged as {attack_type} with {confidence:.1f}% confidence."

    return {
        "summary": summary,
        "context": ATTACK_CONTEXT.get(attack_type, "No additional context available for this attack type."),
        "reasons": reasons,
    }