"""
Potatoo — Reconnaissance Module
Passive & Active recon: DNS, WHOIS, headers, tech fingerprinting, subdomain enum
"""

import re
import socket
import ssl
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import List, Dict, Any, Optional


# ─── Tech Fingerprint Signatures ───────────────────────────────────────────────
TECH_SIGNATURES = {
    # CMS
    "WordPress":     [r"wp-content/", r"wp-includes/", r"/xmlrpc\.php"],
    "Joomla":        [r"/components/com_", r"Joomla!"],
    "Drupal":        [r"Drupal\.settings", r"/sites/default/files/"],
    "Magento":       [r"Mage\.Cookies", r"/skin/frontend/"],
    # Frameworks
    "Laravel":       [r"laravel_session", r"XSRF-TOKEN"],
    "Django":        [r"csrfmiddlewaretoken", r"django"],
    "Ruby on Rails": [r"_rails_", r"X-Runtime.*Ruby"],
    "Spring":        [r"X-Application-Context", r"spring"],
    "ASP.NET":       [r"__VIEWSTATE", r"ASP\.NET_SessionId", r"X-Powered-By.*ASP\.NET"],
    "Express":       [r"X-Powered-By.*Express"],
    "Next.js":       [r"__NEXT_DATA__", r"_next/static/"],
    "Angular":       [r"ng-version=", r"angular\.js"],
    "React":         [r"react-dom", r"__reactFiber"],
    "Vue.js":        [r"vue\.js", r"__vue__"],
    # Servers
    "Apache":        [r"Server.*Apache"],
    "Nginx":         [r"Server.*nginx"],
    "IIS":           [r"Server.*IIS", r"X-Powered-By.*ASP"],
    "Cloudflare":    [r"CF-Ray:", r"Server.*cloudflare"],
    # Languages
    "PHP":           [r"X-Powered-By.*PHP", r"\.php"],
    "Python":        [r"X-Powered-By.*Python", r"wsgi"],
    "Java":          [r"JSESSIONID", r"X-Powered-By.*Servlet"],
}

COMMON_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 4443]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


class Recon:
    def __init__(self, target_url: str, rate_limiter, logger, reporter, session):
        self.target_url   = target_url.rstrip("/")
        self.rl           = rate_limiter
        self.log          = logger
        self.reporter     = reporter
        self.session      = session
        self.parsed       = urllib.parse.urlparse(self.target_url)
        self.host         = self.parsed.netloc.split(":")[0]
        self.results: Dict[str, Any] = {
            "host":         self.host,
            "ips":          [],
            "technologies": [],
            "headers":      {},
            "missing_headers": [],
            "open_ports":   [],
            "subdomains":   [],
            "cookies":      [],
        }

    def run(self) -> Dict[str, Any]:
        self.log.module_start("Reconnaissance")

        self._dns_lookup()
        self._header_analysis()
        self._tech_fingerprint()
        self._check_security_headers()
        self._check_cookies()
        self._check_robots_sitemap()
        self._port_scan()
        self._crt_sh_subdomains()

        self.log.module_done("Reconnaissance")
        return self.results

    # ─── DNS ───────────────────────────────────────────────────────────────────
    def _dns_lookup(self):
        self.log.info(f"DNS lookup → {self.host}")
        try:
            info = socket.getaddrinfo(self.host, None)
            ips  = list({r[4][0] for r in info})
            self.results["ips"] = ips
            for ip in ips:
                self.log.success(f"Resolved: {self.host} → {ip}")
                # Check for cloud hosting
                for cloud, prefix in [("AWS", "ec2"), ("GCP", "google"), ("Azure", "azure"), ("Cloudflare", "104.16")]:
                    if prefix in ip or prefix in self.host:
                        self.results["technologies"].append(cloud)
        except Exception as e:
            self.log.warn(f"DNS lookup failed: {e}")

    # ─── Header Analysis ───────────────────────────────────────────────────────
    def _header_analysis(self):
        self.log.info("Fetching HTTP headers…")
        try:
            self.rl.wait(self.target_url)
            resp = self.session.get(self.target_url, timeout=10)
            self.results["headers"]     = dict(resp.headers)
            self.results["status_code"] = resp.status_code
            self.log.success(f"HTTP {resp.status_code} — {len(resp.content)} bytes")

            # Leaking server info
            server = resp.headers.get("Server", "")
            if server:
                self.log.finding if server else None
                self.reporter.add_finding(
                    title="Server Version Disclosure",
                    severity="LOW",
                    url=self.target_url,
                    description=f"Server header reveals software version: {server}",
                    evidence=f"Server: {server}",
                    remediation="Remove or genericize the Server header.",
                    module="recon",
                    cvss=3.1,
                )

            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                self.reporter.add_finding(
                    title="Technology Version Disclosure (X-Powered-By)",
                    severity="LOW",
                    url=self.target_url,
                    description=f"X-Powered-By reveals framework/language: {x_powered}",
                    evidence=f"X-Powered-By: {x_powered}",
                    remediation="Remove the X-Powered-By header.",
                    module="recon",
                    cvss=3.1,
                )
        except Exception as e:
            self.log.error(f"Header fetch failed: {e}")

    # ─── Tech Fingerprinting ───────────────────────────────────────────────────
    def _tech_fingerprint(self):
        self.log.info("Fingerprinting technology stack…")
        try:
            resp_text = ""
            resp_headers = ""
            self.rl.wait(self.target_url)
            resp      = self.session.get(self.target_url, timeout=10)
            resp_text = resp.text
            resp_headers = str(dict(resp.headers))

            combined = resp_text + resp_headers
            detected = []
            for tech, patterns in TECH_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        if tech not in detected:
                            detected.append(tech)
                            self.log.success(f"Technology detected: {tech}")
                        break

            self.results["technologies"].extend(detected)
            self.results["technologies"] = list(set(self.results["technologies"]))

            if detected:
                self.reporter.add_finding(
                    title="Technology Stack Identified",
                    severity="INFO",
                    url=self.target_url,
                    description=f"Detected technologies: {', '.join(detected)}",
                    evidence=f"Technologies: {', '.join(detected)}",
                    remediation="Minimize technology disclosure in responses.",
                    module="recon",
                    cvss=0.0,
                )
        except Exception as e:
            self.log.warn(f"Tech fingerprint error: {e}")

    # ─── Security Headers ──────────────────────────────────────────────────────
    def _check_security_headers(self):
        self.log.info("Checking security headers…")
        headers = self.results.get("headers", {})
        missing = []
        for h in SECURITY_HEADERS:
            # Case-insensitive check
            found = any(k.lower() == h.lower() for k in headers)
            if not found:
                missing.append(h)

        self.results["missing_headers"] = missing
        if missing:
            self.reporter.add_finding(
                title="Missing Security Headers",
                severity="MEDIUM",
                url=self.target_url,
                description=f"The following security headers are missing: {', '.join(missing)}",
                evidence="\n".join(f"Missing: {h}" for h in missing),
                remediation="Add all recommended security headers to HTTP responses.",
                module="recon",
                cvss=5.3,
            )
            self.log.warn(f"Missing security headers: {', '.join(missing)}")

    # ─── Cookie Analysis ───────────────────────────────────────────────────────
    def _check_cookies(self):
        self.log.info("Analyzing cookies…")
        try:
            self.rl.wait(self.target_url)
            resp = self.session.get(self.target_url, timeout=10)
            cookies = resp.cookies
            for cookie in cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Missing Secure flag")
                if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie.__dict__).lower():
                    issues.append("Missing HttpOnly flag")
                if not cookie.has_nonstandard_attr("SameSite") and "samesite" not in str(cookie.__dict__).lower():
                    issues.append("Missing SameSite attribute")

                self.results["cookies"].append({
                    "name":   cookie.name,
                    "issues": issues,
                })

                if issues:
                    self.reporter.add_finding(
                        title=f"Insecure Cookie: {cookie.name}",
                        severity="MEDIUM",
                        url=self.target_url,
                        description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                        evidence=f"Cookie: {cookie.name}; Issues: {', '.join(issues)}",
                        remediation="Add Secure, HttpOnly, and SameSite=Strict/Lax flags to all cookies.",
                        module="recon",
                        cvss=4.3,
                    )
        except Exception as e:
            self.log.debug(f"Cookie check error: {e}")

    # ─── Robots & Sitemap ──────────────────────────────────────────────────────
    def _check_robots_sitemap(self):
        for path in ["/robots.txt", "/sitemap.xml"]:
            try:
                url = self.target_url + path
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                if resp.status_code == 200:
                    self.log.success(f"Found: {url}")
                    if path == "/robots.txt" and "Disallow:" in resp.text:
                        disallowed = re.findall(r"Disallow:\s*(.+)", resp.text)
                        self.results["robots_disallowed"] = disallowed
                        self.reporter.add_finding(
                            title="robots.txt Reveals Hidden Paths",
                            severity="INFO",
                            url=url,
                            description=f"robots.txt disallows {len(disallowed)} path(s) — these may be sensitive.",
                            evidence="\n".join(disallowed[:10]),
                            remediation="Review whether disallowed paths reveal sensitive endpoints.",
                            module="recon",
                            cvss=0.0,
                        )
            except Exception:
                pass

    # ─── Port Scan ─────────────────────────────────────────────────────────────
    def _port_scan(self):
        self.log.info(f"Port scanning {self.host}…")
        open_ports = []
        for port in COMMON_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.host, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
                    self.log.success(f"Open port: {port}")
            except Exception:
                pass
        self.results["open_ports"] = open_ports

        if len(open_ports) > 2:
            self.reporter.add_finding(
                title="Multiple Open Ports Detected",
                severity="INFO",
                url=self.target_url,
                description=f"Found {len(open_ports)} open port(s): {open_ports}",
                evidence=f"Open ports: {open_ports}",
                remediation="Close unused ports and restrict firewall access.",
                module="recon",
                cvss=0.0,
            )

    # ─── Subdomain Enumeration via crt.sh ──────────────────────────────────────
    def _crt_sh_subdomains(self):
        self.log.info(f"Enumerating subdomains via crt.sh for {self.host}…")
        try:
            url  = f"https://crt.sh/?q=%.{self.host}&output=json"
            self.rl.wait(url)
            req  = urllib.request.Request(url, headers={"User-Agent": "potatoo-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            subs = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(self.host) and sub != self.host:
                        subs.add(sub)
            self.results["subdomains"] = sorted(subs)
            if subs:
                self.log.success(f"Found {len(subs)} subdomains")
                self.reporter.add_finding(
                    title=f"Subdomains Discovered ({len(subs)})",
                    severity="INFO",
                    url=self.target_url,
                    description=f"Certificate transparency logs revealed {len(subs)} subdomains.",
                    evidence="\n".join(sorted(subs)[:20]),
                    remediation="Review all subdomains for outdated/vulnerable services.",
                    module="recon",
                    cvss=0.0,
                )
        except Exception as e:
            self.log.debug(f"crt.sh lookup failed: {e}")
