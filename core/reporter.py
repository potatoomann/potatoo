"""
Potatoo Core — HTML + JSON Report Generator
"""

import json
import os
import datetime
from typing import List, Dict, Any


class Reporter:
    def __init__(self, target: str, output_path: str = "reports"):
        self.target      = target
        self.output_path = output_path
        self.findings: List[Dict[str, Any]] = []
        self.scan_meta   = {
            "target":    target,
            "start_time": datetime.datetime.now().isoformat(),
            "end_time":  None,
            "tool":      "Potatoo v1.0.0",
        }
        os.makedirs(output_path, exist_ok=True)

    def add_finding(
        self,
        title: str,
        severity: str,
        url: str = "",
        description: str = "",
        evidence: str = "",
        remediation: str = "",
        module: str = "",
        cvss: float = 0.0,
    ):
        """Record a vulnerability finding."""
        finding = {
            "id":          len(self.findings) + 1,
            "title":       title,
            "severity":    severity.upper(),
            "url":         url,
            "description": description,
            "evidence":    evidence[:2000] if evidence else "",
            "remediation": remediation,
            "module":      module,
            "cvss":        cvss,
            "timestamp":   datetime.datetime.now().isoformat(),
        }
        self.findings.append(finding)
        return finding

    def finish(self):
        self.scan_meta["end_time"] = datetime.datetime.now().isoformat()

    def save_json(self) -> str:
        """Save findings as JSON."""
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"potatoo_{ts}.json"
        path = os.path.join(self.output_path, name)
        data = {
            "meta":     self.scan_meta,
            "findings": self.findings,
            "summary":  self._summary_stats(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return path

    def save_html(self) -> str:
        """Save findings as a styled HTML report."""
        ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        name = f"potatoo_{ts}.html"
        path = os.path.join(self.output_path, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self._render_html())
        return path

    def _summary_stats(self) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _severity_color(self, sev: str) -> str:
        return {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#44cc44",
            "INFO":     "#44aaff",
        }.get(sev, "#888888")

    def _severity_badge(self, sev: str) -> str:
        color = self._severity_color(sev)
        return f'<span class="badge" style="background:{color}">{sev}</span>'

    def _render_html(self) -> str:
        stats   = self._summary_stats()
        total   = sum(stats.values())
        target  = self.target
        ts      = self.scan_meta.get("start_time", "")

        findings_html = ""
        for f in sorted(self.findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x.get("severity","INFO"))):
            color    = self._severity_color(f["severity"])
            badge    = self._severity_badge(f["severity"])
            evidence = f.get("evidence", "")
            evidence_html = f'<div class="evidence"><pre>{_esc(evidence)}</pre></div>' if evidence else ""
            remediation   = f.get("remediation", "")
            rem_html = f'<p class="remediation"><strong>🛡️ Remediation:</strong> {_esc(remediation)}</p>' if remediation else ""
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {color}">
              <div class="finding-header">
                <span class="finding-id">#{f['id']}</span>
                {badge}
                <span class="finding-title">{_esc(f['title'])}</span>
                <span class="module-tag">{_esc(f.get('module',''))}</span>
              </div>
              <div class="finding-body">
                {"<p><strong>🔗 URL:</strong> <a href='" + _esc(f['url']) + "' target='_blank'>" + _esc(f['url']) + "</a></p>" if f.get('url') else ""}
                <p>{_esc(f.get('description',''))}</p>
                {evidence_html}
                {rem_html}
              </div>
            </div>"""

        if not findings_html:
            findings_html = '<p class="no-findings">✅ No vulnerabilities found during this scan.</p>'

        stats_cards = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            color = self._severity_color(sev)
            cnt   = stats.get(sev, 0)
            stats_cards += f"""
            <div class="stat-card" style="border-top:3px solid {color}">
              <div class="stat-num" style="color:{color}">{cnt}</div>
              <div class="stat-label">{sev}</div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Potatoo Report — {_esc(target)}</title>
  <style>
    :root {{
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --dim: #8b949e; --accent: #58a6ff;
    }}
    * {{ box-sizing: border-box; margin:0; padding:0; }}
    body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; padding:2rem; }}
    .header {{ display:flex; align-items:center; gap:1.5rem; padding:2rem; background:var(--surface);
               border-radius:12px; margin-bottom:2rem; border:1px solid var(--border); }}
    .logo {{ font-size:3rem; }}
    .header h1 {{ font-size:2rem; color:var(--accent); }}
    .header p {{ color:var(--dim); margin-top:.4rem; }}
    .stats {{ display:flex; gap:1rem; margin-bottom:2rem; flex-wrap:wrap; }}
    .stat-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
                  padding:1.2rem 1.5rem; flex:1; min-width:120px; text-align:center; }}
    .stat-num {{ font-size:2.5rem; font-weight:700; }}
    .stat-label {{ font-size:.8rem; color:var(--dim); margin-top:.3rem; letter-spacing:.05em; }}
    .total-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
                   padding:1rem 2rem; display:flex; align-items:center; justify-content:space-between;
                   margin-bottom:2rem; }}
    .total-card span {{ color:var(--dim); }}
    .total-card strong {{ font-size:1.5rem; color:var(--text); }}
    .section-title {{ font-size:1.3rem; font-weight:600; margin-bottom:1rem;
                      border-bottom:1px solid var(--border); padding-bottom:.5rem; color:var(--accent); }}
    .finding {{ background:var(--surface); border:1px solid var(--border); border-radius:8px;
                margin-bottom:1rem; overflow:hidden; }}
    .finding-header {{ display:flex; align-items:center; gap:.75rem; padding:1rem 1.25rem;
                       background:rgba(255,255,255,.02); flex-wrap:wrap; }}
    .finding-id {{ color:var(--dim); font-size:.85rem; }}
    .badge {{ padding:.2rem .6rem; border-radius:4px; font-size:.75rem; font-weight:700;
              color:#000; letter-spacing:.05em; }}
    .finding-title {{ font-weight:600; flex:1; }}
    .module-tag {{ background:#21262d; color:var(--dim); padding:.15rem .5rem;
                   border-radius:4px; font-size:.75rem; font-family:monospace; }}
    .finding-body {{ padding:1rem 1.25rem; border-top:1px solid var(--border); }}
    .finding-body p {{ margin-bottom:.6rem; line-height:1.6; }}
    .evidence {{ background:#0d1117; border:1px solid var(--border); border-radius:6px;
                 padding:.75rem; margin:.6rem 0; overflow-x:auto; }}
    .evidence pre {{ font-family:monospace; font-size:.82rem; color:#79c0ff;
                     white-space:pre-wrap; word-break:break-all; }}
    .remediation {{ background:rgba(88,166,255,.08); border-left:3px solid var(--accent);
                    padding:.6rem .9rem; border-radius:0 6px 6px 0; margin-top:.5rem; }}
    .no-findings {{ text-align:center; padding:3rem; color:var(--dim); font-size:1.2rem; }}
    a {{ color:var(--accent); }}
    .footer {{ text-align:center; color:var(--dim); font-size:.85rem; margin-top:3rem; padding-top:1.5rem;
               border-top:1px solid var(--border); }}
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">🥔</div>
    <div>
      <h1>Potatoo Security Report</h1>
      <p>Target: <strong>{_esc(target)}</strong> &nbsp;|&nbsp; Scanned: {_esc(ts[:19].replace('T',' '))}</p>
    </div>
  </div>

  <div class="stats">{stats_cards}</div>

  <div class="total-card">
    <span>Total Findings</span>
    <strong>{total}</strong>
  </div>

  <div class="section-title">Vulnerability Findings</div>
  {findings_html}

  <div class="footer">
    Generated by <strong>Potatoo v1.0.0</strong> — For authorized penetration testing only
  </div>
</body>
</html>"""


def _esc(s: str) -> str:
    """HTML escape."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
