from datetime import datetime

from markupsafe import Markup, escape

from .collectors import PROVIDERS


def timeago(dt):
    if not dt:
        return "never"
    secs = (datetime.utcnow() - dt).total_seconds()
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= n:
            return f"{int(secs // n)}{unit} ago"
    return "just now"


def md(text):
    """Tiny, safe markdown: escape first, then **bold**, `code`, ```blocks``` and newlines."""
    import re
    s = str(escape(text or ""))
    s = re.sub(r"```(?:\w+)?\n(.*?)```", lambda m: f"<pre><code>{m.group(1)}</code></pre>", s, flags=re.S)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    parts = re.split(r"(<pre>.*?</pre>)", s, flags=re.S)
    s = "".join(p if p.startswith("<pre>") else p.replace("\n", "<br>") for p in parts)
    return Markup(s)


def sparkline(values, width=320, height=64, pad=4):
    """Server-rendered trend line (SVG). Prints, needs no JS, and ships no chart library."""
    vals = [v for v in (values or []) if v is not None]
    if not vals:
        return Markup("")
    lo, hi = 0, 100
    n = len(vals)
    step = (width - 2 * pad) / max(1, n - 1)
    pts = [(pad + i * step if n > 1 else width / 2, pad + (height - 2 * pad) * (1 - (v - lo) / (hi - lo))) for i, v in enumerate(vals)]
    line = " ".join(f"{x:.1f},{y:.1f}" for x, y in pts)
    area = f"{pts[0][0]:.1f},{height - pad} " + line + f" {pts[-1][0]:.1f},{height - pad}"
    grid = "".join(f'<line class="gl" x1="0" x2="{width}" y1="{pad + (height - 2 * pad) * (1 - g / 100):.1f}" y2="{pad + (height - 2 * pad) * (1 - g / 100):.1f}"/>'
                   for g in (40, 60, 80))
    lx, ly = pts[-1]
    return Markup(f'<svg class="spark" viewBox="0 0 {width} {height}" preserveAspectRatio="none" role="img" '
                  f'aria-label="Posture score over the last {n} scans, from {vals[0]} to {vals[-1]}">{grid}'
                  f'<polygon class="ar" points="{area}"/><polyline class="ln" points="{line}"/>'
                  f'<circle class="pt" cx="{lx:.1f}" cy="{ly:.1f}" r="3"/></svg>')


def score_band(score):
    """Words and the matching severity for a 0-100 posture / compliance score."""
    s = score or 0
    if s >= 80:
        return {"label": "Strong", "sev": "low"}
    if s >= 60:
        return {"label": "Needs attention", "sev": "medium"}
    if s >= 40:
        return {"label": "At risk", "sev": "high"}
    return {"label": "Critical exposure", "sev": "critical"}


def register_filters(app):
    app.jinja_env.filters["sparkline"] = sparkline
    import math
    app.jinja_env.filters["cos"] = math.cos
    app.jinja_env.filters["sin"] = math.sin
    app.jinja_env.globals["score_band"] = score_band
    app.jinja_env.filters["timeago"] = timeago
    app.jinja_env.filters["md"] = md
    app.jinja_env.globals["PROVIDERS"] = PROVIDERS
    from . import __version__
    app.jinja_env.globals["APP_VERSION"] = __version__
