"""
Potatoo — Vulnerability Scanner (Additional Checks)
Directory bruteforce, subdomain takeover, information disclosure, HTTP smuggling indicators
"""

import re
import os
import urllib.parse
from typing import List, Dict


SUBDOMAIN_TAKEOVER_PATTERNS = {
    "GitHub Pages":    r"There isn't a GitHub Pages site here",
    "Heroku":          r"No such app",
    "Shopify":         r"Sorry, this shop is currently unavailable",
    "Fastly":          r"Fastly error: unknown domain",
    "Pantheon":        r"404 error unknown site in header",
    "Tumblr":          r"Whatever you were looking for doesn't live here",
    "Squarespace":     r"No Such Account",
    "Zendesk":         r"Help Center Closed",
    "AWS S3":          r"The specified bucket does not exist",
    "Unbounce":        r"The requested URL was not found on this server",
    "Ghost":           r"The thing you were looking for is no longer here",
    "WordPress.com":   r"Do you want to register",
    "SendGrid":        r"The URL you're trying to reach is not a valid SendGrid URL",
    "UserVoice":       r"This UserVoice subdomain is currently available",
    "Pingdom":         r"This public report page has not been activated",
    "Tilda":           r"Please renew your subscription",
}

ERROR_DISCLOSURE_PATTERNS = [
    (r"Exception in thread", "Java Stack Trace Exposed"),
    (r"Traceback \(most recent call last\)", "Python Traceback Exposed"),
    (r"Fatal error:.*on line \d+", "PHP Fatal Error Exposed"),
    (r"Microsoft.*ODBC.*Driver.*SQL", "ODBC Error Message Exposed"),
    (r"Uncaught.*Exception", "Unhandled Exception Exposed"),
    (r"Warning:.*mysql_", "MySQL Warning Exposed"),
    (r"ORA-\d{5}", "Oracle Error Exposed"),
    (r"<b>Warning</b>:.*in <b>.*</b> on line", "PHP Warning Exposed"),
    (r"System\..*Exception", ".NET Exception Exposed"),
    (r"ActiveRecord::.*Error", "Ruby on Rails Error Exposed"),
    (r"ActionView::.*Error", "Rails ActionView Error Exposed"),
    (r"SQLSTATE\[", "SQL State Error Exposed"),
    (r"cannot open.*No such file or directory", "File System Error Exposed"),
    (r"permission denied.*socket", "System Error Exposed"),
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/cpanel", "/cpanel/", "/phpmyadmin",
    "/pma", "/manage", "/management", "/console", "/dashboard",
    "/control", "/controlpanel", "/panel", "/backend", "/cms",
    "/superuser", "/sysadmin",
]


class VulnScanner:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session

    def run(self, subdomains: List[str], urls: List[str]) -> None:
        self.log.module_start("Vulnerability Scanner")
        self._check_error_disclosure(urls)
        self._check_subdomain_takeover(subdomains)
        self._check_admin_panels()
        self._check_http_response_splitting()
        self._check_crlf_injection()
        self._directory_bruteforce()
        self.log.module_done("Vulnerability Scanner")

    def _check_error_disclosure(self, urls: List[str]):
        self.log.info("Checking for error/stack trace disclosure…")
        # Test with deliberate bad inputs
        test_urls = [self.target_url + "/nonexistent_path_xyz_12345"]
        test_urls += [u for u in urls if "?" in u][:5]

        for url in test_urls:
            parsed = urllib.parse.urlparse(url)
            # Try to cause errors
            if parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                for param in list(params.keys())[:2]:
                    test_params          = {k: v[0] for k, v in params.items()}
                    test_params[param]   = "'; DROP TABLE users; --"
                    error_url            = parsed._replace(
                        query=urllib.parse.urlencode(test_params)
                    ).geturl()
                    urls.append(error_url)

        for url in urls[:20]:
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=10)
                self.rl.notify_response(url, resp.status_code)
                for pattern, name in ERROR_DISCLOSURE_PATTERNS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self.reporter.add_finding(
                            title=f"Error/Debug Information Disclosure: {name}",
                            severity="MEDIUM",
                            url=url,
                            description=f"{name} found in response — reveals internal implementation details.",
                            evidence=f"Pattern: {pattern}\nSnippet: {re.findall(pattern, resp.text, re.IGNORECASE)[0][:200]}",
                            remediation="Configure error pages to show generic messages. Disable debug mode in production.",
                            module="vuln_scanner",
                            cvss=5.3,
                        )
                        self.log.finding("MEDIUM", f"Error disclosure: {name}", url)
            except Exception:
                pass

    def _check_subdomain_takeover(self, subdomains: List[str]):
        if not subdomains:
            return
        self.log.info(f"Checking {len(subdomains)} subdomains for takeover…")
        parsed = urllib.parse.urlparse(self.target_url)
        scheme = parsed.scheme

        for sub in subdomains[:30]:
            url = f"{scheme}://{sub}"
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                for provider, pattern in SUBDOMAIN_TAKEOVER_PATTERNS.items():
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        self.reporter.add_finding(
                            title=f"Subdomain Takeover Possible: {sub} ({provider})",
                            severity="HIGH",
                            url=url,
                            description=f"Subdomain '{sub}' appears to be pointing to an unclaimed {provider} resource.",
                            evidence=f"Provider signature: {pattern}\nResponse snippet: {resp.text[:300]}",
                            remediation=f"Remove the DNS record for '{sub}' or claim the {provider} resource immediately.",
                            module="vuln_scanner",
                            cvss=8.1,
                        )
                        self.log.finding("HIGH", f"Subdomain takeover: {sub}", url)
            except Exception:
                pass

    def _check_admin_panels(self):
        self.log.info(f"Checking {len(ADMIN_PATHS)} admin panel paths…")
        for path in ADMIN_PATHS:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200 and any(
                    kw in resp.text.lower() for kw in ["login", "password", "admin", "dashboard", "username"]
                ):
                    self.reporter.add_finding(
                        title=f"Admin Panel Exposed: {path}",
                        severity="HIGH",
                        url=url,
                        description=f"An administrative interface is publicly accessible at '{path}'.",
                        evidence=f"HTTP {resp.status_code} — admin panel detected",
                        remediation="Restrict admin panels to internal IPs. Add IP whitelist, MFA, and VPN requirement.",
                        module="vuln_scanner",
                        cvss=7.5,
                    )
                    self.log.finding("HIGH", f"Admin panel exposed: {path}", url)
                elif resp.status_code == 403:
                    # 403 means it exists but is restricted — still worth noting
                    self.reporter.add_finding(
                        title=f"Admin Path Exists (Access Forbidden): {path}",
                        severity="LOW",
                        url=url,
                        description=f"Path '{path}' returns 403 — admin resource exists but is access-controlled.",
                        evidence=f"HTTP 403 at {url}",
                        remediation="Ensure this path is properly protected with authentication and authorization.",
                        module="vuln_scanner",
                        cvss=2.7,
                    )
            except Exception:
                pass

    def _check_http_response_splitting(self):
        self.log.info("Checking for HTTP response splitting / header injection…")
        params_with_redirect = [
            "redirect", "url", "next", "return", "location", "Location"
        ]
        for param in params_with_redirect:
            test_url = f"{self.target_url}/?{param}=%0d%0aX-Injected-Header:+potatoo-test"
            try:
                self.rl.wait(test_url)
                resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                self.rl.notify_response(test_url, resp.status_code)
                if "X-Injected-Header" in resp.headers:
                    self.reporter.add_finding(
                        title="HTTP Header Injection (CRLF/Response Splitting)",
                        severity="HIGH",
                        url=test_url,
                        description=f"Parameter '{param}' allows CRLF injection into HTTP response headers.",
                        evidence=f"Injected header 'X-Injected-Header' appeared in response.",
                        remediation="Sanitize user input to remove CR/LF characters before using in headers.",
                        module="vuln_scanner",
                        cvss=7.2,
                    )
                    self.log.finding("HIGH", "CRLF/Header injection", test_url)
                    break
            except Exception:
                pass

    def _check_crlf_injection(self):
        """Check for CRLF injection via Set-Cookie header."""
        test_url = f"{self.target_url}/?q=%0d%0aSet-Cookie:+potatoo=injected"
        try:
            self.rl.wait(test_url)
            resp = self.session.get(test_url, timeout=8, allow_redirects=False)
            if "potatoo=injected" in str(resp.cookies) or "potatoo=injected" in resp.headers.get("Set-Cookie", ""):
                self.reporter.add_finding(
                    title="CRLF Injection via Set-Cookie",
                    severity="HIGH",
                    url=test_url,
                    description="CRLF injection allows setting arbitrary cookies.",
                    evidence="Injected cookie 'potatoo=injected' appeared in response.",
                    remediation="Sanitize CR/LF from all user input used in headers.",
                    module="vuln_scanner",
                    cvss=7.2,
                )
        except Exception:
            pass

    def _directory_bruteforce(self):
        """Brute-force common directories using built-in wordlist."""
        self.log.info("Directory brute-force (common paths)…")
        wordlist_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlists", "paths.txt")
        if not os.path.exists(wordlist_path):
            return

        with open(wordlist_path, "r") as f:
            paths = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        found = []
        for i, path in enumerate(paths[:200]):  # Limit to 200 in scanner
            url = self.target_url + "/" + path.lstrip("/")
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                self.log.progress(i + 1, min(200, len(paths)), path)
                if resp.status_code in (200, 301, 302, 403) and url not in [self.target_url, self.target_url + "/"]:
                    found.append(f"[{resp.status_code}] {url}")
                    if resp.status_code == 200:
                        self.reporter.add_finding(
                            title=f"Directory/File Found: /{path}",
                            severity="INFO",
                            url=url,
                            description=f"Path '/{path}' is accessible (HTTP {resp.status_code}).",
                            evidence=f"HTTP {resp.status_code}",
                            remediation="Review if this path should be publicly accessible.",
                            module="vuln_scanner",
                            cvss=0.0,
                        )
            except Exception:
                pass

        if found:
            self.log.success(f"Directory bruteforce found {len(found)} paths")
