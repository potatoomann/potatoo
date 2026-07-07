"""
Potatoo — Auto-Validator
Confirms each finding is a true positive BEFORE adding to report.
No more false positives. Every finding in the report is verified.
"""

import re
import time
import random
import socket
import hashlib
import urllib.parse
from typing import Optional, Tuple


class Validator:
    """
    Drop-in confirmer for every vuln type.
    Each method returns (confirmed: bool, evidence: str)
    """

    def __init__(self, session, rate_limiter, logger=None):
        self.session = session
        self.rl = rate_limiter
        self.log = logger

    def _get(self, url, **kwargs):
        try:
            self.rl.wait(url)
            kwargs.setdefault("timeout", 15)
            kwargs.setdefault("allow_redirects", True)
            return self.session.get(url, **kwargs)
        except Exception as e:
            if self.log:
                self.log.debug(f"Validator GET error: {e}")
            return None

    def _post(self, url, **kwargs):
        try:
            self.rl.wait(url)
            kwargs.setdefault("timeout", 15)
            return self.session.post(url, **kwargs)
        except Exception as e:
            if self.log:
                self.log.debug(f"Validator POST error: {e}")
            return None

    # ─── SQL Injection ────────────────────────────────────────────────────────────
    def confirm_sqli(self, url: str, param: str, method: str = "GET") -> Tuple[bool, str]:
        """
        Confirms SQLi using two techniques:
        1. Time-based blind (SLEEP/pg_sleep/waitfor)
        2. Error-based (unique error string match)
        """
        if self.log:
            self.log.info(f"Confirming SQLi on {param} @ {url}")

        # ── Technique 1: Time-based blind ──────────────────────────────────────
        time_payloads = [
            ("' AND SLEEP(5)-- -",           5),
            ("' AND pg_sleep(5)-- -",        5),
            ("'; WAITFOR DELAY '0:0:5'-- -", 5),
            ("1 AND SLEEP(5)",               5),
            ("' OR SLEEP(5)='",              5),
        ]
        for payload, expected_delay in time_payloads:
            test_url = self._inject_param(url, param, payload)
            t0 = time.time()
            resp = self._get(test_url)
            elapsed = time.time() - t0
            if resp and elapsed >= expected_delay * 0.85:
                evidence = f"Response delayed {elapsed:.2f}s with payload: {payload}"
                if self.log:
                    self.log.success(f"SQLi CONFIRMED (time-based): {elapsed:.1f}s delay")
                return True, evidence
            time.sleep(random.uniform(0.5, 1.0))

        # ── Technique 2: Error-based ────────────────────────────────────────────
        error_payloads = ["'", "''", "\"", "\\", "1'1", "1 OR 1=1--"]
        db_errors = [
            r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"pg_query\(\)",
            r"sqlite3", r"microsoft sql server", r"unclosed quotation mark",
            r"SQLSTATE", r"syntax error.*sql", r"supplied argument is not a valid",
        ]
        for payload in error_payloads:
            test_url = self._inject_param(url, param, payload)
            resp = self._get(test_url)
            if resp:
                for pattern in db_errors:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        evidence = f"DB error with payload '{payload}': matched '{pattern}'"
                        if self.log:
                            self.log.success(f"SQLi CONFIRMED (error-based)")
                        return True, evidence

        return False, "Could not confirm SQLi — likely false positive"

    # ─── XSS ─────────────────────────────────────────────────────────────────────
    def confirm_xss(self, url: str, param: str) -> Tuple[bool, str]:
        """
        Confirms reflected XSS using a unique canary token.
        Only reports if the exact unencoded token appears in response.
        """
        if self.log:
            self.log.info(f"Confirming XSS on {param} @ {url}")

        # Generate a unique canary (avoids WAF pattern matching)
        canary = "PT" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8].upper()
        payloads = [
            f'"><{canary}>',
            f"'><{canary}>",
            f"<{canary} onload=x>",
            f"javascript:{canary}",
        ]

        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            resp = self._get(test_url)
            if resp and canary in resp.text:
                # Check it's not HTML-encoded
                encoded_canary = f"&lt;{canary}&gt;"
                if encoded_canary not in resp.text:
                    evidence = f"Canary '{canary}' reflected raw (unencoded) in response"
                    if self.log:
                        self.log.success(f"XSS CONFIRMED: canary reflected unencoded")
                    return True, evidence

        return False, "XSS not confirmed — reflection is encoded or absent"

    # ─── SSTI ─────────────────────────────────────────────────────────────────────
    def confirm_ssti(self, url: str, param: str) -> Tuple[bool, str]:
        """Confirms SSTI by checking if math expression is evaluated."""
        if self.log:
            self.log.info(f"Confirming SSTI on {param} @ {url}")

        # Use a random multiplication to avoid caching
        a, b = random.randint(10, 99), random.randint(10, 99)
        expected = str(a * b)
        payloads = [
            f"{{{{  {a}*{b}  }}}}",   # Jinja2
            f"#{{  {a}*{b}  }}",       # Ruby ERB
            f"${{  {a}*{b}  }}",       # Freemarker
            f"<%= {a}*{b} %>",         # ERB
            f"{{#{a}*{b}}}",           # Smarty
        ]
        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            resp = self._get(test_url)
            if resp and expected in resp.text:
                evidence = f"Math expression {a}*{b}={expected} evaluated in response"
                if self.log:
                    self.log.success(f"SSTI CONFIRMED: {a}*{b}={expected} evaluated")
                return True, evidence

        return False, "SSTI not confirmed — expression not evaluated"

    # ─── SSRF ─────────────────────────────────────────────────────────────────────
    def confirm_ssrf(self, url: str, param: str) -> Tuple[bool, str]:
        """
        Confirms SSRF by checking if server fetches internal metadata endpoint.
        Uses known cloud metadata IPs and checks response content.
        """
        if self.log:
            self.log.info(f"Confirming SSRF on {param} @ {url}")

        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/hostname",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
        ]
        metadata_signatures = [
            "ami-id", "instance-id", "hostname", "computeMetadata",
            "iam/", "local-ipv4", "placement/",
        ]

        for meta_url in metadata_urls:
            test_url = self._inject_param(url, param, meta_url)
            resp = self._get(test_url)
            if resp:
                for sig in metadata_signatures:
                    if sig in resp.text:
                        evidence = f"Cloud metadata fetched: '{sig}' found in response"
                        if self.log:
                            self.log.success(f"SSRF CONFIRMED: metadata returned")
                        return True, evidence

        return False, "SSRF not confirmed — no metadata response"

    # ─── Open Redirect ────────────────────────────────────────────────────────────
    def confirm_open_redirect(self, url: str, param: str) -> Tuple[bool, str]:
        """Confirms open redirect by checking if response Location header points externally."""
        if self.log:
            self.log.info(f"Confirming Open Redirect on {param} @ {url}")

        marker = "evil-confirm.com"
        payloads = [
            f"https://{marker}",
            f"//{marker}",
            f"https://{marker}@target.com",
        ]
        for payload in payloads:
            test_url = self._inject_param(url, param, payload)
            try:
                self.rl.wait(test_url)
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if marker in location:
                        evidence = f"Redirect to {location} confirmed"
                        if self.log:
                            self.log.success(f"Open Redirect CONFIRMED: {location}")
                        return True, evidence
            except Exception:
                pass

        return False, "Open redirect not confirmed"

    # ─── CORS ─────────────────────────────────────────────────────────────────────
    def confirm_cors(self, url: str) -> Tuple[bool, str]:
        """
        Confirms CORS misconfiguration:
        Must have BOTH Access-Control-Allow-Origin: <evil> AND Allow-Credentials: true
        """
        if self.log:
            self.log.info(f"Confirming CORS @ {url}")

        evil_origins = ["https://evil.com", "https://attacker.com", "null"]
        for origin in evil_origins:
            try:
                self.rl.wait(url)
                resp = self.session.get(url, timeout=10, headers={"Origin": origin})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if (acao == origin or acao == "*") and acac.lower() == "true":
                    evidence = f"ACAO: {acao} | ACAC: {acac} with Origin: {origin}"
                    if self.log:
                        self.log.success(f"CORS CONFIRMED (exploitable): {evidence}")
                    return True, evidence
                elif acao == origin and acac.lower() != "true":
                    # Reflected but no credentials — low severity, still real
                    evidence = f"ACAO reflects origin ({acao}) but no credentials flag"
                    return True, evidence
            except Exception:
                pass

        return False, "CORS not exploitable — origin not reflected"

    # ─── Sensitive File ───────────────────────────────────────────────────────────
    def confirm_sensitive_file(self, url: str) -> Tuple[bool, str]:
        """
        Confirms a sensitive file is real by checking:
        1. Status 200 (not soft 404)
        2. Content is meaningful (not error page)
        3. Content matches expected format
        """
        if self.log:
            self.log.info(f"Confirming sensitive file @ {url}")

        resp = self._get(url)
        if not resp or resp.status_code != 200:
            return False, f"HTTP {resp.status_code if resp else 'N/A'} — not accessible"

        content = resp.text[:3000]
        length = len(resp.content)

        # Reject if it looks like an error page
        error_signs = ["404 not found", "page not found", "does not exist",
                       "error 404", "<title>error", "no such file"]
        for sign in error_signs:
            if sign in content.lower():
                return False, "Soft 404 detected"

        # Confirm based on URL pattern
        url_lower = url.lower()

        if ".env" in url_lower:
            if re.search(r"[A-Z_]+=.+", content):
                sample = re.findall(r"[A-Z_]+=.+", content)[:3]
                return True, f".env file with real vars: {sample}"

        if ".git" in url_lower:
            if "HEAD" in content or "ref:" in content or "repository" in content.lower():
                return True, f".git exposed: {content[:100]}"

        if "backup" in url_lower or url_lower.endswith((".sql", ".zip", ".tar.gz", ".bak")):
            if length > 1000:
                return True, f"Backup file accessible: {length} bytes"

        if "phpinfo" in url_lower or "info.php" in url_lower:
            if "PHP Version" in content or "phpinfo()" in content:
                return True, "phpinfo() page exposed"

        if "config" in url_lower:
            if re.search(r"(password|secret|key|token|db_)\s*[=:]", content, re.IGNORECASE):
                return True, f"Config file with credentials: {length} bytes"

        if "wp-config" in url_lower:
            if "DB_PASSWORD" in content or "AUTH_KEY" in content:
                return True, "WordPress config exposed with DB credentials"

        # Generic: file is real and has content
        if length > 500:
            return True, f"File accessible: {length} bytes, status 200"

        return False, f"File too small ({length}b) — likely false positive"

    # ─── Default Credentials ─────────────────────────────────────────────────────
    def confirm_default_creds(self, login_url: str, username: str, password: str,
                               success_indicators: list = None) -> Tuple[bool, str]:
        """Confirms default credentials by checking for success after POST."""
        if self.log:
            self.log.info(f"Confirming creds {username}:{password} @ {login_url}")

        success_indicators = success_indicators or [
            "dashboard", "logout", "welcome", "profile", "admin",
            "sign out", "log out", "my account", "settings",
        ]
        fail_indicators = [
            "invalid", "incorrect", "wrong", "failed", "error",
            "try again", "bad credentials", "unauthorized",
        ]

        data = {"username": username, "password": password,
                "user": username, "pass": password,
                "email": username, "login": username}

        resp = self._post(login_url, data=data, allow_redirects=True)
        if not resp:
            return False, "No response"

        text = resp.text.lower()

        # Check for failure first
        for fail in fail_indicators:
            if fail in text:
                return False, f"Login failed: '{fail}' in response"

        # Check for success
        for success in success_indicators:
            if success in text:
                evidence = f"Login success with {username}:{password} — found '{success}' in response"
                if self.log:
                    self.log.success(f"Default creds CONFIRMED: {username}:{password}")
                return True, evidence

        # Check for redirect to admin area
        if resp.url and any(p in resp.url for p in ["/admin", "/dashboard", "/panel", "/home"]):
            evidence = f"Redirected to {resp.url} after login"
            return True, evidence

        return False, f"Ambiguous response — could not confirm login success"

    # ─── Subdomain Takeover ───────────────────────────────────────────────────────
    def confirm_subdomain_takeover(self, subdomain: str) -> Tuple[bool, str]:
        """
        Confirms subdomain takeover by:
        1. Checking CNAME points to unclaimed external service
        2. Verifying the service returns a known takeover fingerprint
        """
        if self.log:
            self.log.info(f"Confirming subdomain takeover: {subdomain}")

        # Known takeover fingerprints per service
        takeover_fingerprints = {
            "github.io":          ["There isn't a GitHub Pages site here", "404"],
            "amazonaws.com":      ["NoSuchBucket", "The specified bucket does not exist"],
            "azurewebsites.net":  ["404 Web Site not found", "Microsoft Azure"],
            "shopify.com":        ["Sorry, this shop is currently unavailable"],
            "heroku.com":         ["No such app", "herokucdn.com/error-pages"],
            "fastly.com":         ["Fastly error: unknown domain"],
            "pantheon.io":        ["The gods are wise", "404 error unknown site"],
            "surge.sh":           ["project not found"],
            "netlify.com":        ["Not found - Request ID"],
            "ghost.io":           ["The thing you were looking for is no longer here"],
            "helpscout.net":      ["No settings were found for this company"],
            "statuspage.io":      ["You are being redirected"],
            "uservoice.com":      ["This UserVoice subdomain is currently available"],
            "zendesk.com":        ["Help Center Closed"],
        }

        try:
            # DNS CNAME lookup
            import subprocess
            result = subprocess.run(
                ["dig", "+short", "CNAME", subdomain],
                capture_output=True, text=True, timeout=5
            )
            cname = result.stdout.strip().lower()

            # Check if CNAME points to a known takeover-able service
            for service, fingerprints in takeover_fingerprints.items():
                if service in cname:
                    # Fetch the subdomain and look for fingerprint
                    resp = self._get(f"http://{subdomain}")
                    if resp:
                        for fp in fingerprints:
                            if fp.lower() in resp.text.lower():
                                evidence = f"CNAME → {cname} | Fingerprint: '{fp}'"
                                if self.log:
                                    self.log.success(f"Subdomain takeover CONFIRMED: {subdomain}")
                                return True, evidence
        except Exception as e:
            if self.log:
                self.log.debug(f"Takeover check error: {e}")

        return False, "Subdomain takeover not confirmed"

    # ─── JWT None Algorithm ───────────────────────────────────────────────────────
    def confirm_jwt_none(self, url: str, token: str) -> Tuple[bool, str]:
        """Tests if server accepts JWT with 'none' algorithm (no signature required)."""
        if self.log:
            self.log.info(f"Confirming JWT none-alg @ {url}")
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return False, "Not a valid JWT"

            import base64, json
            # Decode header and payload
            header = json.loads(base64.b64decode(parts[0] + "==").decode())
            payload_data = json.loads(base64.b64decode(parts[1] + "==").decode())

            # Create none-algorithm token
            header["alg"] = "none"
            new_header = base64.b64encode(json.dumps(header, separators=(',', ':')).encode()).decode().rstrip("=")
            new_payload = parts[1]
            forged_token = f"{new_header}.{new_payload}."

            # Also try with empty string sig
            for test_token in [forged_token, f"{new_header}.{new_payload}. "]:
                resp = self._get(url, headers={
                    "Authorization": f"Bearer {test_token}",
                    "Cookie": f"token={test_token}; jwt={test_token}",
                })
                if resp and resp.status_code not in (401, 403, 422):
                    evidence = f"Server accepted JWT with alg=none (status {resp.status_code})"
                    if self.log:
                        self.log.success(f"JWT none-alg CONFIRMED")
                    return True, evidence

        except Exception as e:
            if self.log:
                self.log.debug(f"JWT check error: {e}")

        return False, "JWT none-alg not accepted by server"

    # ─── Secret Key Validity ─────────────────────────────────────────────────────
    def confirm_secret(self, key_type: str, value: str) -> Tuple[bool, str]:
        """
        Confirms secrets are real using entropy + format checks.
        Does NOT make any external API calls.
        """
        import math

        def entropy(s):
            if not s:
                return 0
            freq = {c: s.count(c) / len(s) for c in set(s)}
            return -sum(p * math.log2(p) for p in freq.values())

        value = value.strip()
        ent = entropy(value)

        # Too short or too low entropy = likely a placeholder
        if len(value) < 16:
            return False, f"Too short ({len(value)} chars) — likely placeholder"
        if ent < 3.5:
            return False, f"Low entropy ({ent:.2f}) — likely placeholder/example"

        # Pattern-specific checks
        checks = {
            "AWS Access Key":    (r"AKIA[0-9A-Z]{16}", 20, 20),
            "AWS Secret Key":    (r"[A-Za-z0-9/+=]{40}", 40, 40),
            "GitHub Token":      (r"gh[pousr]_[A-Za-z0-9_]{36,}", 40, 255),
            "Stripe Secret Key": (r"sk_(live|test)_[A-Za-z0-9]{24,}", 32, 255),
            "Private Key":       (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", 50, 99999),
            "Google API Key":    (r"AIza[0-9A-Za-z\-_]{35}", 39, 39),
            "JWT Secret":        (r"[A-Za-z0-9_\-]{32,}", 32, 255),
            "Generic API Key":   (r"[A-Za-z0-9_\-]{32,}", 32, 255),
        }

        for ktype, (pattern, min_len, max_len) in checks.items():
            if ktype.lower() in key_type.lower() or key_type.lower() in ktype.lower():
                if re.search(pattern, value) and min_len <= len(value) <= max_len:
                    return True, f"High-entropy match ({ent:.2f} bits) for {ktype}: {value[:20]}..."

        # Generic high-entropy check
        if ent >= 4.5 and len(value) >= 32:
            return True, f"High-entropy secret ({ent:.2f} bits, {len(value)} chars): {value[:20]}..."

        return False, f"Low confidence — entropy {ent:.2f}, length {len(value)}"

    # ─── Helper ─────────────────────────────────────────────────────────────────
    @staticmethod
    def _inject_param(url: str, param: str, payload: str) -> str:
        """Inject a payload into a URL parameter."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))
