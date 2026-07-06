"""
Potatoo — Secret Detection Module
API keys, cloud credentials, private keys, hardcoded passwords, .env exposure
"""

import re
from typing import List, Dict


# ─── Secret Patterns ───────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    # AWS
    ("AWS Access Key",         r"AKIA[0-9A-Z]{16}",                                                    "CRITICAL"),
    ("AWS Secret Key",         r"['\"][0-9a-zA-Z/+]{40}['\"]",                                          "HIGH"),
    ("AWS Session Token",      r"AQoXnyc4piFFiq2[A-Za-z0-9/+=]{200,}",                                 "CRITICAL"),

    # GCP / Google
    ("Google API Key",         r"AIza[0-9A-Za-z\-_]{35}",                                              "HIGH"),
    ("Google OAuth",           r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",               "HIGH"),
    ("GCP Service Account",    r'"type":\s*"service_account"',                                          "CRITICAL"),

    # Azure
    ("Azure Subscription Key", r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",     "MEDIUM"),
    ("Azure Storage Key",      r"AccountKey=[A-Za-z0-9/+=]{88}",                                        "CRITICAL"),

    # Tokens & Keys
    ("GitHub Token",           r"ghp_[A-Za-z0-9]{36}",                                                 "CRITICAL"),
    ("GitHub Token (old)",     r"[0-9a-f]{40}",                                                         "MEDIUM"),
    ("GitLab Token",           r"glpat-[A-Za-z0-9_\-]{20}",                                            "CRITICAL"),
    ("Slack Token",            r"xox[baprs]-([0-9a-zA-Z]{10,48})",                                     "HIGH"),
    ("Slack Webhook",          r"https://hooks\.slack\.com/services/T[A-Z0-9]{10}/B[A-Z0-9]{10}/[A-Za-z0-9]{24}", "HIGH"),
    ("Stripe Secret Key",      r"sk_live_[0-9a-zA-Z]{24}",                                             "CRITICAL"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24}",                                             "MEDIUM"),
    ("Twilio Account SID",     r"AC[a-z0-9]{32}",                                                       "HIGH"),
    ("Twilio Auth Token",      r"[0-9a-f]{32}",                                                         "MEDIUM"),
    ("SendGrid API Key",       r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",                        "HIGH"),
    ("Mailgun API Key",        r"key-[0-9a-zA-Z]{32}",                                                  "HIGH"),
    ("NPM Token",              r"npm_[A-Za-z0-9]{36}",                                                  "HIGH"),
    ("PyPI Token",             r"pypi-[A-Za-z0-9_\-]{80,}",                                            "HIGH"),
    ("Heroku API Key",         r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "HIGH"),
    ("Dropbox Token",          r"sl\.[A-Za-z0-9\-_]{130,}",                                            "HIGH"),
    ("Telegram Bot Token",     r"[0-9]{9}:[A-Za-z0-9_\-]{35}",                                        "HIGH"),

    # Private Keys
    ("RSA Private Key",        r"-----BEGIN RSA PRIVATE KEY-----",                                      "CRITICAL"),
    ("EC Private Key",         r"-----BEGIN EC PRIVATE KEY-----",                                       "CRITICAL"),
    ("OpenSSH Private Key",    r"-----BEGIN OPENSSH PRIVATE KEY-----",                                  "CRITICAL"),
    ("PGP Private Key",        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",                                "CRITICAL"),
    ("Generic Private Key",    r"-----BEGIN PRIVATE KEY-----",                                          "CRITICAL"),

    # Passwords
    ("Hardcoded Password",     r'(?i)(password|passwd|pwd|secret|key)\s*[=:]\s*["\'][^"\']{4,}["\']',  "HIGH"),
    ("Database URL",           r"(?i)(mysql|postgres|mongodb|redis|amqp)://[^\s\"']+:[^\s\"']+@",       "CRITICAL"),
    ("JDBC Connection String", r"jdbc:[a-z]+://[^\s]+",                                                  "HIGH"),
    ("Basic Auth in URL",      r"https?://[^:]+:[^@]+@",                                                "HIGH"),

    # Generic secrets
    ("Generic API Key",        r"(?i)api[_\-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",           "HIGH"),
    ("Generic Token",          r"(?i)token\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",                   "HIGH"),
    ("Generic Secret",         r"(?i)secret\s*[=:]\s*['\"][A-Za-z0-9_\-]{8,}['\"]",                   "MEDIUM"),
]

# Paths to check for exposed secrets
SECRET_PATHS = [
    "/.env", "/.env.local", "/.env.prod", "/.env.development", "/.env.example",
    "/.git/config", "/.git/HEAD",
    "/config.json", "/config.yml", "/config.yaml",
    "/secrets.json", "/secrets.yml",
    "/app/config", "/application.properties",
    "/WEB-INF/web.xml", "/WEB-INF/applicationContext.xml",
    "/settings.py", "/local_settings.py",
    "/wp-config.php",
    "/database.yml",
    "/credentials.json",
    "/.aws/credentials",
]


class SecretDetector:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session

    def run(self, urls: List[str], js_files: List[str]) -> None:
        self.log.module_start("Secret Detection")
        self._check_secret_paths()
        self._scan_pages_for_secrets(urls[:30])
        self._scan_js_for_secrets(js_files[:20])
        self.log.module_done("Secret Detection")

    def _check_secret_paths(self):
        self.log.info(f"Checking {len(SECRET_PATHS)} secret exposure paths…")
        for path in SECRET_PATHS:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200 and len(resp.content) > 10:
                    # Scan the response for actual secrets
                    findings = self._scan_text(resp.text, url)
                    if findings:
                        for f in findings:
                            self.log.finding(f["severity"], f["title"], url)
                    else:
                        # Still report as exposed file
                        self.reporter.add_finding(
                            title=f"Sensitive File Exposed: {path}",
                            severity="HIGH",
                            url=url,
                            description=f"Sensitive file '{path}' is publicly accessible.",
                            evidence=f"HTTP 200 — content preview: {resp.text[:300]}",
                            remediation=f"Restrict or remove '{path}' from public access.",
                            module="secrets",
                            cvss=7.5,
                        )
            except Exception as e:
                self.log.debug(f"Secret path check error {path}: {e}")

    def _scan_pages_for_secrets(self, urls: List[str]):
        self.log.info(f"Scanning {len(urls)} pages for embedded secrets…")
        for url in urls:
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=10)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200:
                    self._scan_text(resp.text, url)
            except Exception:
                pass

    def _scan_js_for_secrets(self, js_files: List[str]):
        self.log.info(f"Scanning {len(js_files)} JavaScript files for secrets…")
        for url in js_files:
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=10)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200:
                    self._scan_text(resp.text, url)
            except Exception:
                pass

    def _scan_text(self, text: str, url: str) -> List[Dict]:
        """Scan text for secret patterns."""
        found = []
        seen  = set()

        for name, pattern, severity in SECRET_PATTERNS:
            matches = re.findall(pattern, text)
            for match in matches:
                match_str = str(match)[:100]
                key       = f"{name}:{match_str[:20]}"
                if key in seen:
                    continue
                seen.add(key)

                # Ignore obvious false positives
                if match_str in ("0000000000000000", "1234567890abcdef"):
                    continue

                self.reporter.add_finding(
                    title=f"Secret Exposed: {name}",
                    severity=severity,
                    url=url,
                    description=f"A potential {name} was found in the response.",
                    evidence=f"Pattern match: {match_str}",
                    remediation=f"Remove '{name}' from source code/responses. Rotate the credential immediately. Use environment variables or secret managers.",
                    module="secrets",
                    cvss=9.1 if severity == "CRITICAL" else 7.5 if severity == "HIGH" else 5.0,
                )
                found.append({"title": f"Secret: {name}", "severity": severity})
                self.log.finding(severity, f"Secret found: {name}", url)

        return found
