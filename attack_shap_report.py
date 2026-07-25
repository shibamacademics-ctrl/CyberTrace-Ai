"""
attack_shap_report.py
======================
Detects attacks in network traffic and explains WHY each one was flagged,
using SHAP. Produces ONE self-contained HTML file (attack_report.html) that
you open directly in a browser -- no Flask, no server, no internet CDN,
no templates folder. That's what makes it portable: it will run the same
way on your laptop, in Google Colab, in a Jupyter notebook, on Replit, or
inside an offline auto-grader.

Why this version is different from a typical Flask+Chart.js dashboard:
  1. Model: GradientBoostingClassifier (built into scikit-learn) instead of
     plain RandomForest -- no xgboost/lightgbm install needed, still a
     proper boosted-tree model.
  2. Explainability has a SAFE FALLBACK: if the `shap` package isn't
     installed, OR if it's installed but throws at runtime (version
     mismatches, unsupported model internals, etc.), the script
     automatically computes a permutation-importance-based local
     explanation instead of crashing. You still get a working
     "why was this flagged" chart either way.
  3. One SHAP explainer is built ONCE and reused for the global chart and
     every per-event explanation. (An earlier version of this script
     rebuilt a brand-new `shap.Explainer` for every single event -- that's
     what caused the slow runs and the "Background dataset ... subsampling"
     warning spam.) TreeExplainer with tree_path_dependent perturbation
     needs no background sample at all, so it's both faster and exact for
     tree ensembles like this one.
  4. Output is a single static HTML report (charts embedded as inline
     base64 images) -- nothing to serve, nothing that can 404, nothing
     that depends on a CDN being reachable.

Usage:
    pip install scikit-learn pandas matplotlib          # always required
    pip install shap                                    # optional, recommended
    python attack_shap_report.py
    # then open attack_report.html in any browser
"""

import base64
import io
import webbrowser
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")  # headless rendering -- works on servers/notebooks/CI too
import matplotlib.pyplot as plt

from sklearn.datasets import make_classification
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.model_selection import train_test_split

# Try to use real SHAP. If it's not installed, fall back gracefully
# instead of crashing the whole script.
try:
    import shap
    HAVE_SHAP = True
except ImportError:
    HAVE_SHAP = False


FEATURE_NAMES = [
    "duration", "src_bytes", "dst_bytes", "wrong_fragment", "urgent",
    "count", "srv_count", "serror_rate", "same_srv_rate",
    "diff_srv_rate", "dst_host_count", "dst_host_srv_count",
]
N_EVENTS_IN_REPORT = 12  # how many individual events to explain in the report

# Two-tone, colour-blind-friendly palette used everywhere (charts + HTML)
COLOR_ATTACK = "#e8a33d"   # amber -- "toward attack"
COLOR_NORMAL = "#3fb8c4"   # cyan  -- "toward normal"


# ----------------------------------------------------------------------
# 1. Data -- swap this for pd.read_csv("your_traffic.csv") in production.
#    Keep FEATURE_NAMES matching your real column names.
# ----------------------------------------------------------------------
def build_dataset(n_samples=4000, seed=42):
    X, y = make_classification(
        n_samples=n_samples, n_features=len(FEATURE_NAMES),
        n_informative=8, n_redundant=2, weights=[0.7, 0.3],
        flip_y=0.02, class_sep=1.2, random_state=seed,
    )
    X = np.abs(X)  # traffic stats are non-negative
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y  # 1 = attack, 0 = normal
    return df


# ----------------------------------------------------------------------
# 2. Model
# ----------------------------------------------------------------------
def train_model(X_train, y_train):
    model = GradientBoostingClassifier(
        n_estimators=200, max_depth=3, learning_rate=0.1, random_state=42,
    )
    model.fit(X_train, y_train)
    return model


# ----------------------------------------------------------------------
# 3. Explanations -- real SHAP if available, permutation fallback if not
# ----------------------------------------------------------------------
def build_explainer(model):
    """
    Build ONE TreeExplainer for the whole run. tree_path_dependent
    perturbation (the default when you don't pass a background dataset)
    is exact for tree ensembles and needs no background sample, so it
    avoids both the subsampling warnings and the cost of rebuilding an
    explainer for every event.

    Returns the explainer, or None if SHAP isn't usable for this model
    (missing package, or any runtime error) so callers can fall back.
    """
    if not HAVE_SHAP:
        return None
    try:
        return shap.TreeExplainer(model)
    except Exception:
        return None


def _binary_class_values(vals):
    """Normalise a SHAP Explanation's .values to a 2D (n_samples, n_features)
    array of "push toward attack" contributions, regardless of whether this
    SHAP/sklearn version returned a 2D array or a 3D per-class array."""
    vals = np.asarray(vals)
    if vals.ndim == 3:       # (n_samples, n_features, n_classes)
        vals = vals[:, :, 1]
    return vals


def get_global_importance(model, explainer, X_test, y_test):
    """Returns (feature_names, importance_scores, method_label) sorted descending."""
    if explainer is not None:
        try:
            sv = explainer(X_test)
            vals = _binary_class_values(sv.values)
            importance = np.abs(vals).mean(axis=0)
            order = np.argsort(importance)[::-1]
            return ([FEATURE_NAMES[i] for i in order], importance[order],
                     "SHAP (mean |SHAP value|)")
        except Exception:
            pass  # fall through to permutation importance below

    r = permutation_importance(model, X_test, y_test, n_repeats=15, random_state=42)
    importance = r.importances_mean
    order = np.argsort(importance)[::-1]
    return ([FEATURE_NAMES[i] for i in order], importance[order],
             "Permutation importance (SHAP fallback)")


def explain_single_event(model, explainer, X_test, row_idx, background):
    """
    Returns (contributions, used_shap) where contributions is a list of
    (feature, contribution, raw_value) sorted by absolute impact -- the
    numbers that drive the per-event chart.
    """
    row = X_test.iloc[[row_idx]]
    if explainer is not None:
        try:
            sv = explainer(row)
            vals = _binary_class_values(sv.values)[0]
            contributions = list(zip(FEATURE_NAMES, vals))
            contributions.sort(key=lambda c: abs(c[1]), reverse=True)
            raw_values = row.iloc[0].to_dict()
            return [(f, val, raw_values[f]) for f, val in contributions], True
        except Exception:
            pass  # fall through to the permutation-based fallback below

    # Fallback: perturb each feature to its background mean, one at a
    # time, and measure the drop in predicted attack-probability.
    base_prob = model.predict_proba(row)[0, 1]
    contributions = []
    for f in FEATURE_NAMES:
        perturbed = row.copy()
        perturbed[f] = background[f].mean()
        new_prob = model.predict_proba(perturbed)[0, 1]
        contributions.append((f, base_prob - new_prob))
    contributions.sort(key=lambda c: abs(c[1]), reverse=True)
    raw_values = row.iloc[0].to_dict()
    return [(f, val, raw_values[f]) for f, val in contributions], False


# ----------------------------------------------------------------------
# 4. Plain-English narration -- turns SHAP numbers into sentences an
#    analyst can read in two seconds without knowing what SHAP is.
# ----------------------------------------------------------------------
def describe_event(verdict, contributions, background):
    """Builds a short, human-readable explanation of the top drivers."""
    top = contributions[:3]
    parts = []
    for feat, impact, raw_val in top:
        avg = background[feat].mean()
        direction = "higher" if raw_val >= avg else "lower"
        push = "toward ATTACK" if impact >= 0 else "toward NORMAL"
        parts.append(
            f"<b>{feat}</b> was {direction} than the typical value "
            f"({raw_val:.2f} vs. avg {avg:.2f}), pushing the score {push}"
        )
    lead = "flagged as an attack" if verdict == "attack" else "cleared as normal"
    return f"This event was {lead} mainly because " + "; ".join(parts) + "."


# ----------------------------------------------------------------------
# 5. Rendering -- everything becomes an inline base64 PNG, so the HTML
#    file is fully self-contained (works with file:// -- no server).
# ----------------------------------------------------------------------
def fig_to_base64():
    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=150, bbox_inches="tight", transparent=True)
    plt.close()
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def _style_axes(ax):
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color("#3a4658")
    ax.tick_params(colors="#a9b6c9", labelsize=9)
    ax.xaxis.label.set_color("#a9b6c9")
    ax.title.set_color("#e6edf5")


def render_global_chart(names, scores, method):
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    colors = [COLOR_ATTACK] * len(names)
    ax.barh(names[::-1], scores[::-1], color=colors[::-1], height=0.62)
    ax.set_xlabel(method)
    ax.set_title("Which features matter most across all traffic?")
    _style_axes(ax)
    fig.tight_layout()
    return fig_to_base64()


def render_event_chart(event_id, verdict, prob, contributions):
    feats = [f"{c[0]}  ({c[2]:.2f})" for c in contributions]
    impacts = [c[1] for c in contributions]
    colors = [COLOR_ATTACK if v >= 0 else COLOR_NORMAL for v in impacts]
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    ax.barh(feats[::-1], impacts[::-1], color=colors[::-1], height=0.62)
    ax.axvline(0, color="#5a6b82", linewidth=0.8)
    ax.set_title(f"Case #{event_id} -- predicted {verdict.upper()} ({prob*100:.1f}% attack probability)")
    ax.set_xlabel("Contribution toward ATTACK (amber) vs. NORMAL (cyan)")
    _style_axes(ax)
    fig.tight_layout()
    return fig_to_base64()


# ----------------------------------------------------------------------
# 6. Build the single HTML report
# ----------------------------------------------------------------------
def confidence_meter_html(prob, verdict):
    pct = prob * 100 if verdict == "attack" else (1 - prob) * 100
    color = COLOR_ATTACK if verdict == "attack" else COLOR_NORMAL
    return f"""
      <div class="meter">
        <div class="meter-track">
          <div class="meter-fill" style="width:{pct:.1f}%; background:{color};"></div>
        </div>
        <div class="meter-label">{prob*100:.1f}% attack probability</div>
      </div>"""


def build_event_card(idx, verdict, prob, contributions, explainer_used, background):
    badge_class = "attack" if verdict == "attack" else "normal"
    img = render_event_chart(idx, verdict, prob, contributions)
    narration = describe_event(verdict, contributions, background)
    method_tag = "SHAP" if explainer_used else "fallback"

    rows = "\n".join(
        f"""<tr>
              <td class="mono">{feat}</td>
              <td class="mono">{raw:.2f}</td>
              <td><span class="chip {'attack' if impact >= 0 else 'normal'}">
                    {'toward ATTACK' if impact >= 0 else 'toward NORMAL'}
                  </span></td>
            </tr>"""
        for feat, impact, raw in contributions[:5]
    )

    return f"""
      <div class="panel event" id="case-{idx}">
        <div class="event-head">
          <div>
            <span class="case-no">Case #{idx}</span>
            <span class="badge {badge_class}">{verdict.upper()}</span>
            <span class="method-tag">{method_tag}</span>
          </div>
        </div>
        {confidence_meter_html(prob, verdict)}
        <p class="narration">{narration}</p>
        <img src="data:image/png;base64,{img}" alt="Feature contribution chart for case {idx}">
        <table class="drivers">
          <thead><tr><th>Feature</th><th>Observed value</th><th>Effect</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>"""


def build_html(global_img, method, top_feature_names, event_cards, index_chips, stats):
    events_html = "\n".join(event_cards)
    index_html = "\n".join(index_chips)
    top3 = ", ".join(top_feature_names[:3])
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack Detection -- Explainability Report</title>
<style>
  :root {{
    --bg:#0a0e14; --panel:#10151d; --panel-2:#141b26; --border:#1e2733;
    --text:#e6edf5; --muted:#8b98ab; --attack:{COLOR_ATTACK}; --normal:{COLOR_NORMAL};
  }}
  * {{ box-sizing:border-box; }}
  body {{
    background:var(--bg); color:var(--text); margin:0; padding:0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:36px 20px 80px; }}

  header.top {{ border-bottom:1px solid var(--border); padding-bottom:20px; margin-bottom:28px; }}
  header.top .eyebrow {{ color:var(--attack); font-size:12px; letter-spacing:.12em;
    text-transform:uppercase; font-family: ui-monospace, monospace; margin-bottom:6px; }}
  header.top h1 {{ font-size:26px; margin:0 0 6px; letter-spacing:-.01em; }}
  header.top .sub {{ color:var(--muted); font-size:13.5px; }}

  .stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:22px 0 8px; }}
  .stat-card {{ background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px 16px; }}
  .stat-card .label {{ color:var(--muted); font-size:11px; text-transform:uppercase;
    letter-spacing:.06em; margin-bottom:6px; }}
  .stat-card .value {{ font-size:19px; font-weight:600; font-family: ui-monospace, monospace; }}

  h2 {{ font-size:13px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em;
    margin:44px 0 14px; padding-bottom:8px; border-bottom:1px solid var(--border); }}

  .explainer {{ background:var(--panel-2); border:1px solid var(--border); border-left:3px solid var(--attack);
    border-radius:6px; padding:16px 18px; margin-bottom:8px; font-size:13.5px; line-height:1.6; color:#c7d2e0; }}
  .explainer b {{ color:var(--text); }}

  .panel {{ background:var(--panel); border:1px solid var(--border); border-radius:8px;
    padding:18px; margin-bottom:16px; }}
  .takeaway {{ font-size:13px; color:var(--muted); margin-top:10px; }}
  .takeaway b {{ color:var(--text); }}
  img {{ max-width:100%; border-radius:6px; display:block; margin:10px 0; }}

  .badge {{ padding:3px 9px; border-radius:4px; font-size:11px; font-weight:700;
    letter-spacing:.04em; margin-left:8px; }}
  .attack.badge, .chip.attack {{ background:rgba(232,163,61,.15); color:var(--attack); }}
  .normal.badge, .chip.normal {{ background:rgba(63,184,196,.15); color:var(--normal); }}
  .chip {{ padding:2px 8px; border-radius:10px; font-size:11px; font-weight:600; }}

  .index {{ display:flex; flex-wrap:wrap; gap:8px; margin-bottom:20px; }}
  .index a {{ text-decoration:none; color:var(--muted); background:var(--panel);
    border:1px solid var(--border); border-radius:6px; padding:6px 10px; font-size:12px;
    font-family: ui-monospace, monospace; }}
  .index a .dot {{ display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:6px; }}
  .index a.attack .dot {{ background:var(--attack); }}
  .index a.normal .dot {{ background:var(--normal); }}

  .case-no {{ font-family: ui-monospace, monospace; font-size:13px; color:var(--muted); }}
  .method-tag {{ float:right; font-size:10px; color:var(--muted); border:1px solid var(--border);
    border-radius:4px; padding:2px 6px; text-transform:uppercase; letter-spacing:.05em; }}
  .event-head {{ margin-bottom:10px; }}

  .meter-track {{ background:#1a2230; border-radius:6px; height:10px; overflow:hidden; }}
  .meter-fill {{ height:100%; border-radius:6px; }}
  .meter-label {{ font-size:11px; color:var(--muted); margin-top:6px; font-family: ui-monospace, monospace; }}

  .narration {{ font-size:13.5px; line-height:1.6; color:#c7d2e0; margin:14px 0; }}
  .narration b {{ color:var(--text); }}

  table.drivers {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:12.5px; }}
  table.drivers th {{ text-align:left; color:var(--muted); font-weight:600; font-size:11px;
    text-transform:uppercase; letter-spacing:.05em; padding:6px 8px; border-bottom:1px solid var(--border); }}
  table.drivers td {{ padding:7px 8px; border-bottom:1px solid var(--border); color:#c7d2e0; }}

  footer {{ margin-top:40px; color:var(--muted); font-size:11.5px; border-top:1px solid var(--border);
    padding-top:16px; font-family: ui-monospace, monospace; }}

  @media (max-width:640px) {{
    .stat-grid {{ grid-template-columns:repeat(2,1fr); }}
    .method-tag {{ float:none; display:inline-block; margin-left:8px; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="top">
    <div class="eyebrow">XAI &middot; Intrusion Detection</div>
    <h1>Attack Detection &mdash; Explainability Report</h1>
    <div class="sub">Generated {generated} &middot; every verdict below is backed by a feature-level explanation, not a black box</div>
  </header>

  <div class="stat-grid">
    <div class="stat-card"><div class="label">Model</div><div class="value">{stats['model']}</div></div>
    <div class="stat-card"><div class="label">Test accuracy</div><div class="value">{stats['accuracy']:.1%}</div></div>
    <div class="stat-card"><div class="label">Explanation method</div><div class="value">{method.split(' (')[0]}</div></div>
    <div class="stat-card"><div class="label">Attacks in test set</div><div class="value">{stats['attack_rate']:.1%}</div></div>
  </div>

  <div class="explainer">
    <b>How to read this report:</b> for each flagged event, the model outputs an attack probability,
    then SHAP explains <i>which network-traffic features pushed that score up or down</i> and by how much.
    Amber bars push a case toward ATTACK; cyan bars pull it back toward NORMAL. Longer bars mean bigger
    influence. You don't need to know how SHAP works to use this &mdash; each case also includes a
    plain-English sentence naming its top drivers.
  </div>

  <h2>Global Feature Importance</h2>
  <div class="panel">
    <img src="data:image/png;base64,{global_img}" alt="Global feature importance chart">
    <div class="takeaway">Across all traffic in the test set, <b>{top3}</b> are the features the model
      relies on most when telling attacks apart from normal activity.</div>
  </div>

  <h2>Case Index &middot; {stats['n_events']} events, sorted by attack probability</h2>
  <div class="index">{index_html}</div>

  <h2>Per-Event Explanations</h2>
  {events_html}

  <footer>
    shap_available={stats['have_shap']} &middot; explanation_method="{method}" &middot;
    report is fully self-contained (no server, no external requests)
  </footer>
</div>
</body>
</html>"""


def main():
    df = build_dataset()
    X = df[FEATURE_NAMES]
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=42
    )
    X_test = X_test.reset_index(drop=True)
    y_test = y_test.reset_index(drop=True)

    model = train_model(X_train, y_train)
    accuracy = model.score(X_test, y_test)

    explainer = build_explainer(model)  # built ONCE, reused everywhere below

    names, scores, method = get_global_importance(model, explainer, X_test, y_test)
    global_img = render_global_chart(names, scores, method)

    preds = model.predict(X_test)
    probs = model.predict_proba(X_test)[:, 1]

    event_cards, index_chips = [], []
    # Prioritise showing flagged attacks first, so the report is useful at a glance
    order = np.argsort(-probs)[:N_EVENTS_IN_REPORT]
    used_shap_any = False
    for idx in order:
        verdict = "attack" if preds[idx] == 1 else "normal"
        contributions, used_shap = explain_single_event(
            model, explainer, X_test, idx, background=X_train
        )
        used_shap_any = used_shap_any or used_shap
        event_cards.append(build_event_card(idx, verdict, probs[idx], contributions, used_shap, X_train))
        index_chips.append(
            f'<a href="#case-{idx}" class="{verdict}"><span class="dot"></span>'
            f'#{idx} {probs[idx]*100:.0f}%</a>'
        )

    html = build_html(
        global_img, method, names, event_cards, index_chips,
        stats={
            "model": type(model).__name__,
            "accuracy": accuracy,
            "attack_rate": y_test.mean(),
            "n_events": len(order),
            "have_shap": HAVE_SHAP,
        },
    )

    out_path = Path("attack_report.html")
    out_path.write_text(html, encoding="utf-8")
    print(f"Done. Test accuracy: {accuracy:.1%}")
    print(f"SHAP available: {HAVE_SHAP} (global method used: {method}, "
          f"per-event explainer used SHAP: {used_shap_any})")
    print(f"Report written to: {out_path.resolve()}")
    try:
        webbrowser.open(out_path.resolve().as_uri())
    except Exception:
        pass  # headless environments (e.g. Colab, CI) just skip auto-open


if __name__ == "__main__":
    main()
