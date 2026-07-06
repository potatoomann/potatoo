# 🥔 Potatoo — Automated Bug Bounty AI

> **Senior Pentester Intelligence — No APIs — Rate-Limited — Linux Native**

Potatoo is an automated bug bounty and penetration testing tool that mimics the systematic approach of a senior cybersecurity pentester. It operates entirely locally — no external AI APIs are required — and uses a smart rate-limiter to stay under detection/ban thresholds.

---

## ⚡ Quick Install (Linux)

```bash
git clone https://github.com/youruser/potatoo
cd potatoo
chmod +x install.sh
./install.sh
```

After install, run from anywhere:

```bash
potatoo -u https://target.com
```

---

## 🚀 Usage

```bash
# Basic scan (stealthy by default)
potatoo -u https://example.com

# Balanced scan (more coverage)
potatoo -u https://example.com --level 3

# Full aggressive scan
potatoo -u https://example.com --level 5

# Recon only
potatoo -u https://example.com --mode recon

# Single module
potatoo -u https://example.com --module injections
potatoo -u https://example.com --module secrets
potatoo -u https://example.com --module auth

# Custom output path
potatoo -u https://example.com --output ~/reports/client_scan

# Verbose/debug
potatoo -u https://example.com -v
```

---

## 🧠 How It Works

Potatoo runs in phases, just like a real pentester:

```
1. Recon         → DNS, WHOIS, headers, tech stack, subdomains (crt.sh)
2. Crawl         → Sitemap, forms, JS files, parameters
3. Adapt         → Adjusts tests based on detected tech (PHP→SQLi, React→XSS, etc.)
4. Misconfig     → CORS, headers, SSL/TLS, sensitive paths, HTTP methods
5. Secrets       → API keys, cloud creds, private keys in responses
6. JS Analysis   → Hidden endpoints, source maps, GraphQL, sensitive comments
7. Auth Testing  → Default creds, JWT weaknesses, brute-force protection
8. Injections    → SQLi, XSS, SSTI, SSRF, Open Redirect
9. Vuln Scanner  → Subdomain takeover, admin panels, error disclosure, CRLF
```

---

## 📊 Scan Levels

| Level | Style | Delay | Threads | Req/Min |
|-------|-------|-------|---------|---------|
| 1 | Very Stealthy | 3–6s | 1 | ~10 |
| **2** | **Stealthy (Default)** | **1–3s** | **2** | **~30** |
| 3 | Balanced | 0.5–2s | 3 | ~60 |
| 4 | Aggressive | 0.2–1s | 5 | ~120 |
| 5 | Maximum | 0.1–0.5s | 8 | ~300 |

Auto-backoff on HTTP 429/503 responses (waits 30s then resumes).

---

## 🔍 Vulnerability Coverage

| Category | Checks |
|----------|--------|
| **Injection** | SQL (error + time-based blind), XSS, SSTI, SSRF, Open Redirect, Command Injection |
| **Authentication** | Default credentials, SQL auth bypass, JWT (none alg, weak secrets), brute-force protection, HTTP verb tampering |
| **Misconfiguration** | CORS, missing headers, insecure cookies, HTTP methods, SSL/TLS, clickjacking, directory listing |
| **Secrets** | 40+ patterns: AWS/GCP/Azure keys, GitHub tokens, Stripe, private keys, DB connection strings |
| **Information Disclosure** | Version leaks, stack traces, .env files, .git exposure, source maps |
| **Infrastructure** | Subdomain takeover, admin panel exposure, subdomain enumeration |
| **JavaScript** | Hidden API endpoints, sensitive comments, GraphQL introspection |

---

## 📁 Output

Reports are saved to `./reports/` (or your `--output` path):

- **HTML Report** — Styled dark-themed report with all findings
- **JSON Report** — Machine-readable structured output

Findings are color-coded:
- 🔴 `CRITICAL` — Immediate exploitation possible (SQLi, RCE, default creds)
- 🟠 `HIGH` — Significant security issue
- 🟡 `MEDIUM` — Notable vulnerability
- 🟢 `LOW` — Minor issue
- 🔵 `INFO` — Informational finding

---

## 🛠️ Requirements

- Python 3.8+
- `requests` library (auto-installed by `install.sh`)

---

## ⚠️ Legal Disclaimer

> This tool is intended **only** for:
> - Authorized penetration testing engagements
> - Bug bounty programs where you have explicit permission
> - Testing your own systems
>
> **Unauthorized scanning is illegal.** You are solely responsible for your actions.

---

## 📜 License

MIT License — See LICENSE file for details.
