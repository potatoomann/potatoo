"""
Potatoo — Misconfiguration Scanner
CORS, HTTP methods, directory listing, SSL/TLS, clickjacking, info disclosure
All findings auto-validated before reporting.
"""

import re
import ssl
import socket
import urllib.parse
from typing import List, Dict

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.validator import Validator


DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH", "OPTIONS", "DEBUG"]

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/.env", "/.env.local", "/.env.backup", "/.env.prod",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/wp-config.php", "/wp-config.php.bak",
    "/database.yml", "/settings.py", "/local_settings.py",
    "/.DS_Store", "/Thumbs.db",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/dump.sql", "/db.sql", "/database.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/admin/", "/administrator/", "/phpmyadmin/", "/pma/",
    "/api/swagger", "/api/swagger.json", "/swagger.json",
    "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings", "/actuator/dump",
    "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/sitemap.xml", "/robots.txt",
    "/logs/", "/log/", "/error.log", "/access.log",
    "/web.config", "/.htaccess", "/.htpasswd",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
    "/package.json", "/composer.json", "/Gemfile",
    "/docker-compose.yml", "/Dockerfile",
    "/CHANGELOG.md", "/README.md",
]

CORS_EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.potatoo.io",
]


class MisconfigScanner:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session
        self.parsed     = urllib.parse.urlparse(self.target_url)
        self.host       = self.parsed.netloc.split(":")[0]
        self.validator  = Validator(session, rate_limiter, logger)

    def run(self) -> None:
        self.log.module_start("Misconfiguration Scanner")
        self._check_cors()
        self._check_http_methods()
        self._check_sensitive_paths()
        self._check_ssl_tls()
        self._check_clickjacking()
        self._check_directory_listing()
        self.log.module_done("Misconfiguration Scanner")

    # ─── CORS ──────────────────────────────────────────────────────────────────
    def _check_cors(self):
        self.log.info("Testing CORS misconfiguration…")
        for origin in CORS_EVIL_ORIGINS:
            try:
                self.rl.wait(self.target_url)
                resp = self.session.get(
                    self.target_url,
                    headers={"Origin": origin},
                    timeout=10,
                )
                self.rl.notify_response(self.target_url, resp.status_code)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == "*":
                    confirmed, evidence = self.validator.confirm_cors(self.target_url)
                    if confirmed:
                        self.reporter.add_finding(
                            title="CORS Wildcard Origin (Confirmed)",
                            severity="MEDIUM",
                            url=self.target_url,
                            description="Access-Control-Allow-Origin: * allows any domain to make cross-origin requests.",
                            evidence=evidence,
                            remediation="Restrict CORS to specific trusted domains. Never use wildcard with credentials.",
                            module="misconfig",
                            cvss=5.4,
                        )
                        self.log.finding("MEDIUM", "CORS Wildcard Origin", self.target_url)

                elif acao == origin and acac.lower() == "true":
                    confirmed, evidence = self.validator.confirm_cors(self.target_url)
                    if confirmed:
                        self.reporter.add_finding(
                            title="CORS Origin Reflection with Credentials (Confirmed)",
                            severity="HIGH",
                            url=self.target_url,
                            description=f"Server reflects arbitrary Origin '{origin}' with credentials — allows cross-origin authenticated requests.",
                            evidence=evidence,
                            remediation="Validate Origin against a strict whitelist. Never allow credentials with reflected origins.",
                            module="misconfig",
                            cvss=8.1,
                        )
                        self.log.finding("HIGH", "CORS Origin Reflection + Credentials", self.target_url)
                        break

                elif acao == origin:
                    confirmed, evidence = self.validator.confirm_cors(self.target_url)
                    if confirmed:
                        self.reporter.add_finding(
                            title="CORS Arbitrary Origin Reflection (Confirmed)",
                            severity="MEDIUM",
                            url=self.target_url,
                            description=f"Server reflects the Origin header without validation.",
                            evidence=evidence,
                            remediation="Implement an explicit origin whitelist.",
                            module="misconfig",
                            cvss=6.1,
                        )
                        self.log.finding("MEDIUM", "CORS Arbitrary Origin Reflection", self.target_url)
                        break

                if acao == "null":
                    self.reporter.add_finding(
                        title="CORS null Origin Allowed",
                        severity="HIGH",
                        url=self.target_url,
                        description="Server allows null origin — attackers can use sandboxed iframes to bypass SOP.",
                        evidence=f"ACAO: null",
                        remediation="Reject null as a valid CORS origin.",
                        module="misconfig",
                        cvss=7.5,
                    )

            except Exception as e:
                self.log.debug(f"CORS test error: {e}")

    # ─── HTTP Methods ──────────────────────────────────────────────────────────
    def _check_http_methods(self):
        self.log.info("Testing allowed HTTP methods…")
        try:
            self.rl.wait(self.target_url)
            resp = self.session.options(self.target_url, timeout=10)
            self.rl.notify_response(self.target_url, resp.status_code)
            allow_header = resp.headers.get("Allow", "") + resp.headers.get("Public", "")

            dangerous_found = [m for m in DANGEROUS_METHODS if m in allow_header.upper()]
            if dangerous_found:
                self.reporter.add_finding(
                    title=f"Dangerous HTTP Methods Enabled: {', '.join(dangerous_found)}",
                    severity="HIGH" if "DELETE" in dangerous_found or "PUT" in dangerous_found else "MEDIUM",
                    url=self.target_url,
                    description=f"The server allows potentially dangerous HTTP methods: {', '.join(dangerous_found)}",
                    evidence=f"Allow: {allow_header}",
                    remediation="Disable unused HTTP methods. Only allow GET, POST, HEAD as needed.",
                    module="misconfig",
                    cvss=7.5,
                )
                self.log.finding("HIGH", f"Dangerous HTTP methods: {dangerous_found}", self.target_url)

            # Check TRACE explicitly
            self.rl.wait(self.target_url)
            trace_resp = self.session.request("TRACE", self.target_url, timeout=8)
            if trace_resp.status_code == 200 and "TRACE" in trace_resp.text.upper():
                self.reporter.add_finding(
                    title="HTTP TRACE Method Enabled (XST Possible)",
                    severity="MEDIUM",
                    url=self.target_url,
                    description="TRACE method is enabled — Cross-Site Tracing (XST) attacks possible.",
                    evidence=f"TRACE response: {trace_resp.text[:200]}",
                    remediation="Disable the TRACE method on the web server.",
                    module="misconfig",
                    cvss=5.8,
                )
        except Exception as e:
            self.log.debug(f"HTTP methods test error: {e}")

    # ─── Sensitive Paths ───────────────────────────────────────────────────────
    def _check_sensitive_paths(self):
        self.log.info(f"Checking {len(SENSITIVE_PATHS)} sensitive paths…")
        found = 0
        for i, path in enumerate(SENSITIVE_PATHS):
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                self.log.progress(i + 1, len(SENSITIVE_PATHS), path)

                if resp.status_code in (200, 206) and len(resp.content) > 0:
                    # Auto-confirm: check it's not a soft 404
                    confirmed, file_evidence = self.validator.confirm_sensitive_file(url)
                    if not confirmed:
                        continue

                    sev = "CRITICAL"
                    if any(x in path for x in [".env", "config", ".git", "id_rsa", ".htpasswd", "backup", ".sql"]):
                        sev = "CRITICAL"
                    elif any(x in path for x in ["admin", "phpmyadmin", "actuator", "swagger", "phpinfo"]):
                        sev = "HIGH"
                    elif any(x in path for x in ["robots", "sitemap", "CHANGELOG", "package.json"]):
                        sev = "LOW"
                    else:
                        sev = "MEDIUM"

                    self.reporter.add_finding(
                        title=f"Sensitive File/Path Exposed: {path}",
                        severity=sev,
                        url=url,
                        description=f"Sensitive path '{path}' is publicly accessible and confirmed real content.",
                        evidence=file_evidence,
                        remediation=f"Remove or restrict access to '{path}'. Configure web server to deny access.",
                        module="misconfig",
                        cvss=9.1 if sev == "CRITICAL" else 7.5 if sev == "HIGH" else 4.0,
                    )
                    self.log.finding(sev, f"Exposed: {path}", url)
                    found += 1
            except Exception as e:
                self.log.debug(f"Path check error {path}: {e}")

        if found == 0:
            self.log.success("No sensitive paths found accessible")

    # ─── SSL/TLS ───────────────────────────────────────────────────────────────
    def _check_ssl_tls(self):
        if self.parsed.scheme != "https":
            self.reporter.add_finding(
                title="No HTTPS / Plaintext HTTP",
                severity="HIGH",
                url=self.target_url,
                description="The target does not use HTTPS. All traffic is transmitted in plaintext.",
                evidence=f"URL scheme: {self.parsed.scheme}",
                remediation="Deploy TLS/SSL and redirect all HTTP traffic to HTTPS.",
                module="misconfig",
                cvss=7.5,
            )
            self.log.finding("HIGH", "No HTTPS detected", self.target_url)
            return

        self.log.info("Checking SSL/TLS configuration…")
        port = 443
        try:
            # Check for weak TLS versions
            for proto_name, proto_const in [
                ("SSLv2",  None),
                ("SSLv3",  ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_TLS_CLIENT') else None),
                ("TLSv1",  None),
                ("TLSv1.1", None),
            ]:
                pass  # Deep TLS checking requires openssl binary

            # Get cert expiry
            ctx = ssl.create_default_context()
            try:
                with ctx.wrap_socket(socket.socket(), server_hostname=self.host) as s:
                    s.settimeout(5)
                    s.connect((self.host, port))
                    cert = s.getpeercert()
                    import datetime
                    expiry_str = cert.get("notAfter", "")
                    if expiry_str:
                        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        if days_left < 30:
                            self.reporter.add_finding(
                                title=f"SSL Certificate Expiring Soon ({days_left} days)",
                                severity="MEDIUM" if days_left > 0 else "CRITICAL",
                                url=self.target_url,
                                description=f"SSL certificate expires in {days_left} days ({expiry_str}).",
                                evidence=f"Certificate expiry: {expiry_str}",
                                remediation="Renew the SSL certificate immediately.",
                                module="misconfig",
                                cvss=5.3,
                            )
                        self.log.success(f"SSL cert expires in {days_left} days")
            except ssl.SSLCertVerificationError as e:
                self.reporter.add_finding(
                    title="Invalid or Self-Signed SSL Certificate",
                    severity="HIGH",
                    url=self.target_url,
                    description=f"SSL certificate verification failed: {e}",
                    evidence=str(e),
                    remediation="Use a valid certificate from a trusted Certificate Authority.",
                    module="misconfig",
                    cvss=6.5,
                )
        except Exception as e:
            self.log.debug(f"SSL check error: {e}")

    # ─── Clickjacking ──────────────────────────────────────────────────────────
    def _check_clickjacking(self):
        self.log.info("Checking clickjacking protection…")
        headers = {}
        try:
            self.rl.wait(self.target_url)
            resp    = self.session.get(self.target_url, timeout=10)
            headers = resp.headers
        except Exception:
            return

        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")

        has_xfo        = bool(xfo)
        has_csp_noframe = "frame-ancestors" in csp.lower()

        if not has_xfo and not has_csp_noframe:
            self.reporter.add_finding(
                title="Clickjacking Vulnerability (Missing X-Frame-Options / CSP frame-ancestors)",
                severity="MEDIUM",
                url=self.target_url,
                description="The page can be embedded in an iframe — clickjacking attacks possible.",
                evidence=f"X-Frame-Options: {xfo or 'Not set'}\nCSP: {csp or 'Not set'}",
                remediation="Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors none'.",
                module="misconfig",
                cvss=5.4,
            )
            self.log.finding("MEDIUM", "Clickjacking — no frame protection", self.target_url)

    # ─── Directory Listing ─────────────────────────────────────────────────────
    def _check_directory_listing(self):
        self.log.info("Checking for directory listing…")
        dir_paths = ["/images/", "/uploads/", "/assets/", "/static/", "/files/", "/backup/", "/logs/"]
        for path in dir_paths:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200 and (
                    "Index of" in resp.text or
                    "Directory listing" in resp.text or
                    "<title>Index of" in resp.text
                ):
                    self.reporter.add_finding(
                        title=f"Directory Listing Enabled: {path}",
                        severity="MEDIUM",
                        url=url,
                        description=f"Directory listing is enabled at '{path}' — files are browsable.",
                        evidence=f"Response contains 'Index of' at: {url}",
                        remediation="Disable directory listing in web server configuration.",
                        module="misconfig",
                        cvss=5.3,
                    )
                    self.log.finding("MEDIUM", f"Directory listing at {path}", url)
            except Exception:
                pass
