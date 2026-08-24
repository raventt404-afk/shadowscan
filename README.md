# 🕵️ ShadowScan

> Passive web & server security scanner for ethical reconnaissance.  
> Built for developers and pentesters who need fast, clean security reports.

```
 ▗▄▄▖▗▖ ▗▖ ▗▄▖ ▗▄▄▄   ▗▄▖ ▗▖ ▗▖     ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▖ 
▐▌   ▐▌ ▐▌▐▌ ▐▌▐▌  █ ▐▌ ▐▌▐▌ ▐▌    ▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌▐▛▚▖▐▌▐▌   ▐▌ ▐▌
 ▝▀▚▖▐▛▀▜▌▐▛▀▜▌▐▌  █ ▐▌ ▐▌▐▌ ▐▌     ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌▐▌ ▝▜▌▐▛▀▀▘▐▛▀▚▖
▗▄▄▞▘▐▌ ▐▌▐▌ ▐▌▐▙▄▄▀ ▝▚▄▞▘▐▙█▟▌    ▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌▐▌  ▐▌▐▙▄▄▖▐▌ ▐▌
```

**Passive • Safe • No Exploits • by RAVEN404**

---

## 📋 What it does

ShadowScan performs passive reconnaissance on a target URL, domain, or IP and generates a professional security report — useful for auditing websites you own or have permission to test.

| Module | What it checks |
|---|---|
| 🌐 DNS | A, MX, TXT, NS, CNAME, AAAA records + zone transfer check |
| 📍 Geo / ASN | Country, city, ISP, ASN, reverse DNS |
| 🔌 Ports | 13 common ports (FTP, SSH, HTTP, RDP, MySQL, etc.) |
| 🔒 SSL | Certificate validity and expiration date |
| 🛡️ HTTP Headers | Security headers audit + cookie flags (Secure, HttpOnly, SameSite) |
| 🔍 Vulnerabilities | SQLi, XSS, CSRF, SSRF, IDOR, Open Redirect, Directory Listing, Info Disclosure |
| 📂 Paths | robots.txt, sitemap.xml, HTML links, JS endpoints, common path probing |
| 🌍 Subdomains | DNS brute-force (wordlist) + Certificate Transparency (crt.sh) |
| 💧 Leaks | Email addresses from HTML, JS, robots.txt, sitemap, contact pages |
| ⚙️ Technologies | WordPress, Drupal, Joomla, React, Next.js, Vue.js, Webpack |

---

## 🚀 Quick Start

**Requirements:** Python 3.9+

```bash
# 1. Clone the repo
git clone https://github.com/raventt404-afk/shadowscan.git
cd ShadowScan

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run
python shadowscan.py
```

> **Windows users:** use `py` instead of `python`
> ```powershell
> py shadowscan.py
> ```

---

## 📄 Output

After scanning, two reports are saved automatically:

```
reports/
├── json/  report_example_com_20260824_215400.json   ← raw data
└── html/  report_example_com_20260824_215400.html   ← client-ready report
```

Open the `.html` file in any browser — no server needed.

---

## 🖥️ Terminal output example

```
🎯 Target: https://example.com
   Domain:  example.com
   IP:      93.184.216.34

  [████████████████████████████░░] 12/13  Vulnerability scan + risk scoring

──────────────────────────────────────────────────────────
  🟡  RISK LEVEL: MEDIUM  (score: 8.5)
──────────────────────────────────────────────────────────

  Key findings:
    • Missing 3 security headers: X-Frame-Options, Permissions-Policy, Referrer-Policy
    • Missing SPF record (email spoofing risk)
    • Cookie 'session' missing HttpOnly flag

  📊 Summary:
     Subdomains found : 7
     Open ports       : 3
     Paths discovered : 24
     Emails leaked    : 2

  📄 JSON report : reports/json/report_example_com_20260824.json
  🌐 HTML report : reports/html/report_example_com_20260824.html
```

---

## ⚠️ Legal Notice

ShadowScan is designed for **passive reconnaissance only** — it does not exploit vulnerabilities or cause harm to target systems.

**Only use on:**
- Websites you own
- Websites you have explicit written permission to test

The author is not responsible for any misuse of this tool.

---

## 📦 Dependencies

| Package | Version | Purpose |
|---|---|---|
| requests | 2.34.2 | HTTP requests |
| python-whois | 0.9.6 | WHOIS lookup |
| dnspython | 2.8.0 | DNS records (MX, TXT, NS, etc.) |
| beautifulsoup4 | 4.15.0 | HTML parsing |
| urllib3 | 2.7.0 | HTTP client |

---

## 🗂️ Project Structure

```
ShadowScan/
├── shadowscan.py          # Entry point
├── requirements.txt
├── core/
│   ├── target_resolver.py # URL / Domain / IP normalization
│   ├── dns_info.py        # DNS records + zone transfer
│   ├── ports.py           # Port scanner
│   ├── ssl_info.py        # SSL certificate check
│   ├── http_audit.py      # Security headers + cookies
│   ├── technologies.py    # CMS / framework detection
│   ├── path_discovery.py  # Path & endpoint discovery
│   ├── subdomains.py      # DNS brute-force subdomains
│   ├── crtsh.py           # crt.sh subdomain discovery
│   ├── whois.py           # WHOIS
│   ├── api_scan.py        # API endpoint detection
│   ├── leaks.py           # Email & secret leak detection
│   ├── vuln_surface.py    # Vulnerability surface scan
│   ├── infra_intel.py     # Geo / ASN / reverse DNS
│   ├── risk.py            # Risk scoring engine
│   └── report_html.py     # HTML report generator
└── reports/
    ├── json/              # Raw JSON reports
    └── html/              # Client-ready HTML reports
```

---

Made with ☕ by **RAVEN404**
