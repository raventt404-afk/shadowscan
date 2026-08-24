#!/usr/bin/env python3
# shadowscan.py — Main entry point for ShadowScan
import os
import json
import requests
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.banner import print_banner
from core.target_resolver import TargetResolver
from core.dns_info import get_dns
from core.ports import scan_ports
from core.ssl_info import check_ssl
from core.technologies import detect_tech
from core.path_discovery import discover_paths
from core.subdomains import find_subdomains
from core.crtsh import find_subdomains_crtsh
from core.whois import get_whois
from core.api_scan import scan_api
from core.vuln_surface import scan_vulnerabilities
from core.risk import calculate_risk
from core.leaks import detect_leaks
from core.http_audit import audit_http
from core.infra_intel import get_infra_intel
from core.report_html import generate_html_report

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}


def ensure_directories():
    os.makedirs("reports/json", exist_ok=True)
    os.makedirs("reports/html", exist_ok=True)


def print_progress(step: str, total: int, current: int):
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    print(f"\r  [{bar}] {current}/{total}  {step:<35}", end="", flush=True)


def main():
    print_banner()

    target_input = input("Введите URL / Domain / IP цели: ").strip()
    if not target_input:
        print("❌ No target provided.")
        return

    resolver = TargetResolver(target_input)

    print(f"\n🎯 Target: {resolver.url}")
    print(f"   Domain:  {resolver.domain}")
    print(f"   IP:      {resolver.ip or 'resolving...'}\n")

    session = requests.Session()
    session.headers.update(HEADERS)
    session.verify = False

    data = {
        "timestamp": datetime.now().isoformat(),
        "target": resolver.as_dict()
    }

    TOTAL_STEPS = 13
    step = 0

    # ── 1. DNS ───────────────────────────────────────────────────────────────
    step += 1
    print_progress("DNS records", TOTAL_STEPS, step)
    data["dns"] = get_dns(resolver.domain)
    if not resolver.ip and data["dns"].get("A"):
        resolver.ip = data["dns"]["A"]

    # ── 2. Infrastructure (Geo/ASN/rDNS) ────────────────────────────────────
    step += 1
    print_progress("Geo / ASN / rDNS", TOTAL_STEPS, step)
    data["infra"] = get_infra_intel(resolver.ip) if resolver.ip else {}

    # ── 3. Ports ─────────────────────────────────────────────────────────────
    step += 1
    print_progress("Port scan", TOTAL_STEPS, step)
    data["ports"] = scan_ports(resolver.ip) if resolver.ip else []

    # ── 4. Main HTTP request (ONE fetch, reused everywhere) ──────────────────
    step += 1
    print_progress("Main page fetch", TOTAL_STEPS, step)
    main_html = ""
    main_response = None
    try:
        r = session.get(resolver.url, timeout=12)
        main_response = r
        if r.status_code == 200:
            main_html = r.text
        data["http"] = {
            "status": r.status_code,
            "server": r.headers.get("Server"),
            "headers": dict(r.headers)
        }
    except Exception as e:
        data["http"] = {"status": "blocked_or_timeout", "error": str(e)}

    # ── 5. HTTP Audit (security headers, cookies) ────────────────────────────
    step += 1
    print_progress("HTTP security audit", TOTAL_STEPS, step)
    data["http_audit"] = audit_http(resolver.url, session=session)

    # ── 6. Technologies ───────────────────────────────────────────────────────
    step += 1
    print_progress("Technology detection", TOTAL_STEPS, step)
    data["technologies"] = detect_tech(resolver.url) if main_html else []

    # ── 7. SSL ────────────────────────────────────────────────────────────────
    step += 1
    print_progress("SSL certificate", TOTAL_STEPS, step)
    data["ssl"] = check_ssl(resolver.domain)

    # ── 8. Subdomains: wordlist DNS brute + crt.sh ───────────────────────────
    step += 1
    print_progress("Subdomain discovery", TOTAL_STEPS, step)
    wordlist_subs = find_subdomains(resolver.base_domain)
    crtsh_subs = find_subdomains_crtsh(resolver.base_domain)
    data["subdomains"] = {
        "wordlist": wordlist_subs,
        "crtsh": crtsh_subs,
        "total": len(wordlist_subs) + len(crtsh_subs)
    }

    # ── 9. WHOIS ──────────────────────────────────────────────────────────────
    step += 1
    print_progress("WHOIS", TOTAL_STEPS, step)
    data["whois"] = get_whois(resolver.base_domain)

    # ── 10. Path discovery (reuse main_html) ─────────────────────────────────
    step += 1
    print_progress("Path discovery", TOTAL_STEPS, step)
    data["paths"] = discover_paths(resolver.url, main_html=main_html)

    # ── 11. API scan ──────────────────────────────────────────────────────────
    step += 1
    print_progress("API endpoint scan", TOTAL_STEPS, step)
    data["api"] = scan_api(resolver.url)

    # ── 12. Leaks (email, API keys) ───────────────────────────────────────────
    step += 1
    print_progress("Leak detection", TOTAL_STEPS, step)
    data["leaks"] = detect_leaks(resolver.url, session, main_html)

    # ── 13. Vulnerabilities + Risk ────────────────────────────────────────────
    step += 1
    print_progress("Vulnerability scan + risk scoring", TOTAL_STEPS, step)
    data["vulnerabilities"] = scan_vulnerabilities(resolver.url, main_html=main_html)
    data["risk"] = calculate_risk(data)

    print()  # newline after progress bar

    # ── Save reports ──────────────────────────────────────────────────────────
    ensure_directories()
    name = (resolver.domain or resolver.ip or "report").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = f"reports/json/report_{name}_{ts}.json"
    html_path = f"reports/html/report_{name}_{ts}.html"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    generate_html_report(data, html_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    risk = data["risk"]
    risk_icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon = risk_icons.get(risk["level"], "⚪")

    print(f"\n{'─'*60}")
    print(f"  {icon}  RISK LEVEL: {risk['level']}  (score: {risk['score']})")
    print(f"{'─'*60}")

    if risk.get("reasons"):
        print("\n  Key findings:")
        for r in risk["reasons"][:8]:
            print(f"    • {r}")
        if len(risk["reasons"]) > 8:
            print(f"    ... and {len(risk['reasons']) - 8} more")

    subcount = data["subdomains"]["total"]
    emails = len(data.get("leaks", {}).get("emails", []))
    ports_open = len(data.get("ports", []))
    paths_found = len(data.get("paths", []))

    print(f"\n  📊 Summary:")
    print(f"     Subdomains found : {subcount}")
    print(f"     Open ports       : {ports_open}")
    print(f"     Paths discovered : {paths_found}")
    print(f"     Emails leaked    : {emails}")

    print(f"\n  📄 JSON report : {json_path}")
    print(f"  🌐 HTML report : {html_path}")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
