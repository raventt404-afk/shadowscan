# core/report_html.py
# Generates a professional HTML report for clients
from datetime import datetime


RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#16a34a",
}

RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}


def _badge(level: str, text: str = None):
    color = RISK_COLORS.get(level, "#6b7280")
    label = text or level
    return f'<span style="background:{color};color:#fff;padding:3px 10px;border-radius:12px;font-size:13px;font-weight:600">{label}</span>'


def _section(title: str, content: str, icon: str = ""):
    return f"""
    <div class="section">
        <h2>{icon} {title}</h2>
        {content}
    </div>"""


def _table(headers: list, rows: list):
    if not rows:
        return '<p class="empty">No data found.</p>'
    th = "".join(f"<th>{h}</th>" for h in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def _list_items(items: list):
    if not items:
        return '<p class="empty">None found.</p>'
    li = "".join(f"<li>{i}</li>" for i in items)
    return f"<ul>{li}</ul>"


def generate_html_report(data: dict, output_path: str):
    target = data.get("target", {})
    domain = target.get("domain") or target.get("ip") or "Unknown"
    url = target.get("url", "")
    ts = data.get("timestamp", datetime.now().isoformat())
    risk = data.get("risk", {})
    risk_level = risk.get("level", "UNKNOWN")
    risk_score = risk.get("score", 0)
    risk_color = RISK_COLORS.get(risk_level, "#6b7280")

    # ── DNS ──────────────────────────────────────────────────────────────────
    dns = data.get("dns", {})
    dns_rows = []
    for rtype, val in dns.items():
        if rtype == "zone_transfer":
            continue
        if isinstance(val, list):
            for v in val:
                dns_rows.append([rtype, v])
        elif val:
            dns_rows.append([rtype, val])

    zone_transfer = dns.get("zone_transfer", False)
    dns_html = _table(["Type", "Value"], dns_rows)
    if zone_transfer:
        dns_html += '<p style="color:#dc2626;font-weight:bold">⚠️ Zone Transfer allowed! Critical misconfiguration.</p>'

    # ── Ports ────────────────────────────────────────────────────────────────
    ports = data.get("ports", [])
    port_rows = []
    for p in ports:
        risk_badge = _badge(p.get("risk", "MEDIUM"), p.get("risk", "MEDIUM"))
        port_rows.append([p.get("port"), p.get("service", ""), risk_badge])
    ports_html = _table(["Port", "Service", "Risk"], port_rows)

    # ── HTTP Audit ───────────────────────────────────────────────────────────
    http_audit = data.get("http_audit", {})
    sec_headers = http_audit.get("security_headers", {})
    missing_headers = http_audit.get("missing_headers", [])
    leaking_headers = http_audit.get("info_leaking_headers", {})
    cookies = http_audit.get("cookies", [])
    https_enforced = http_audit.get("https_enforced", False)

    sh_rows = [[h, v] for h, v in sec_headers.items()]
    sh_rows += [[f'<span style="color:#dc2626">{h}</span>', "❌ MISSING"] for h in missing_headers]
    http_html = _table(["Header", "Value"], sh_rows)

    if leaking_headers:
        http_html += "<h3 style='color:#ea580c'>⚠️ Info-leaking headers</h3>"
        http_html += _table(["Header", "Value"], [[h, v] for h, v in leaking_headers.items()])

    cookie_rows = []
    for c in cookies:
        secure = "✅" if c.get("secure") else "❌"
        httponly = "✅" if c.get("httponly") else "❌"
        samesite = "✅" if c.get("samesite") else "⚠️"
        cookie_rows.append([c.get("name", ""), secure, httponly, samesite])
    if cookie_rows:
        http_html += "<h3>🍪 Cookies</h3>"
        http_html += _table(["Name", "Secure", "HttpOnly", "SameSite"], cookie_rows)

    https_status = "✅ Enforced" if https_enforced else "❌ Not enforced"
    http_html += f"<p><strong>HTTPS redirect:</strong> {https_status}</p>"

    # ── Subdomains ───────────────────────────────────────────────────────────
    subdomains = data.get("subdomains", {})
    wordlist_subs = subdomains.get("wordlist", []) if isinstance(subdomains, dict) else subdomains
    crtsh_subs = subdomains.get("crtsh", []) if isinstance(subdomains, dict) else []
    all_subs = []
    for s in wordlist_subs:
        if isinstance(s, dict):
            all_subs.append([s.get("subdomain", ""), s.get("ip", ""), "DNS Brute"])
        else:
            all_subs.append([s, "", "DNS Brute"])
    for s in crtsh_subs:
        all_subs.append([s, "", "crt.sh"])
    sub_html = _table(["Subdomain", "IP", "Source"], all_subs)

    # ── Vulnerabilities ───────────────────────────────────────────────────────
    vulns = data.get("vulnerabilities", {})
    vuln_rows = []
    for name, status in vulns.items():
        if status == "possible":
            badge = _badge("HIGH", "⚠️ Possible")
        elif status == "likely":
            badge = _badge("MEDIUM", "🔶 Likely")
        elif status == "not_detected":
            badge = _badge("LOW", "✅ Not detected")
        else:
            badge = f'<span style="color:#6b7280">{status}</span>'
        vuln_rows.append([name.replace("_", " ").title(), badge])
    vulns_html = _table(["Vulnerability", "Status"], vuln_rows)

    # ── Leaks ────────────────────────────────────────────────────────────────
    leaks = data.get("leaks", {})
    emails = leaks.get("emails", [])
    api_keys = leaks.get("api_keys", [])
    leaks_html = ""
    if emails:
        leaks_html += f"<h3>📧 Emails found ({len(emails)})</h3>" + _list_items(emails)
    if api_keys:
        leaks_html += f"<h3>🔑 Potential API keys/secrets ({len(api_keys)})</h3>" + _list_items(api_keys[:20])
    if not leaks_html:
        leaks_html = '<p class="empty">No leaks detected.</p>'

    # ── Risk reasons ─────────────────────────────────────────────────────────
    reasons = risk.get("reasons", [])
    risk_html = _list_items(reasons)

    # ── Paths ────────────────────────────────────────────────────────────────
    paths = data.get("paths", [])
    path_rows = []
    for p in paths:
        if isinstance(p, dict):
            status = p.get("status", "")
            path = p.get("path", "")
        else:
            path = str(p)
            status = ""
        color = ""
        if str(status) == "200":
            color = "color:#16a34a"
        elif str(status) == "403":
            color = "color:#d97706"
        path_rows.append([f'<span style="{color}">{path}</span>', status])
    paths_html = _table(["Path", "Status"], path_rows)

    # ── SSL ──────────────────────────────────────────────────────────────────
    ssl = data.get("ssl", {})
    ssl_valid = "✅ Valid" if ssl.get("valid") else "❌ Invalid/Missing"
    ssl_expires = ssl.get("expires", "Unknown")
    ssl_html = f"""
    <p><strong>Status:</strong> {ssl_valid}</p>
    <p><strong>Expires:</strong> {ssl_expires}</p>
    """

    # ── Infra ─────────────────────────────────────────────────────────────────
    infra = data.get("infra", {})
    geo = infra.get("geo_asn", {}) if infra else {}
    rdns = infra.get("reverse_dns", "") if infra else ""
    infra_html = f"""
    <p><strong>Reverse DNS:</strong> {rdns or '—'}</p>
    <p><strong>Country:</strong> {geo.get('country', '—')} {geo.get('country_code', '')}</p>
    <p><strong>City:</strong> {geo.get('city', '—')}</p>
    <p><strong>ISP:</strong> {geo.get('isp', '—')}</p>
    <p><strong>ASN:</strong> {geo.get('asn', '—')}</p>
    <p><strong>Org:</strong> {geo.get('org', '—')}</p>
    """

    # ── Assemble HTML ─────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShadowScan Report — {domain}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #e2e8f0; }}
  .header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 3px solid #7dd3fc;
    padding: 32px 48px;
  }}
  .header h1 {{ font-size: 28px; color: #f8fafc; }}
  .header .meta {{ color: #94a3b8; margin-top: 6px; font-size: 14px; }}
  .risk-badge {{
    display: inline-block;
    background: {risk_color};
    color: #fff;
    font-size: 22px;
    font-weight: 700;
    padding: 8px 24px;
    border-radius: 20px;
    margin-top: 12px;
  }}
  .content {{ padding: 32px 48px; max-width: 1400px; }}
  .section {{
    background: #1e293b;
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 24px;
    border: 1px solid #334155;
  }}
  .section h2 {{
    font-size: 18px;
    color: #7dd3fc;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid #334155;
  }}
  .section h3 {{ color: #94a3b8; font-size: 14px; margin: 14px 0 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #0f172a; color: #7dd3fc; padding: 10px 12px; text-align: left; }}
  td {{ padding: 9px 12px; border-bottom: 1px solid #334155; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #273549; }}
  ul {{ padding-left: 20px; }}
  li {{ padding: 4px 0; font-size: 14px; }}
  p {{ font-size: 14px; padding: 4px 0; }}
  .empty {{ color: #64748b; font-style: italic; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  @media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} .header, .content {{ padding: 20px; }} }}
  .score-box {{
    display: inline-block;
    background: #0f172a;
    border: 2px solid {risk_color};
    border-radius: 10px;
    padding: 10px 20px;
    margin-top: 8px;
  }}
  .score-box span {{ font-size: 32px; font-weight: 800; color: {risk_color}; }}
  .score-box small {{ display: block; color: #94a3b8; font-size: 12px; }}
  footer {{ text-align: center; padding: 20px; color: #475569; font-size: 12px; }}
</style>
</head>
<body>

<div class="header">
  <h1>🕵️ ShadowScan Security Report</h1>
  <div class="meta">
    <strong>Target:</strong> <a href="{url}" style="color:#7dd3fc">{url}</a> &nbsp;|&nbsp;
    <strong>Generated:</strong> {ts[:19].replace("T", " ")} &nbsp;|&nbsp;
    <strong>IP:</strong> {target.get("ip") or "—"}
  </div>
</div>

<div class="content">

  <div class="grid">

    {_section("SSL Certificate", ssl_html, "🔒")}

  </div>

  {_section("HTTP Security Headers", http_html, "🛡️")}

  <div class="grid">

    {_section("DNS Records", dns_html, "🌐")}

    {_section("Infrastructure / Geo / ASN", infra_html, "📍")}

  </div>

  {_section("Vulnerability Surface", vulns_html, "🔍")}

  {_section("Open Ports", ports_html, "🔌")}

  {_section("Discovered Paths & Endpoints", paths_html, "📂")}

  {_section("Subdomains", sub_html, "🌍")}

  {_section("Leaks & Exposed Data", leaks_html, "💧")}

</div>

<footer>
  Generated by <strong>ShadowScan</strong> by RAVEN404 &nbsp;|&nbsp; Passive • Ethical • No Exploits
</footer>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path
