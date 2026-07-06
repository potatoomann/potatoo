"""
Potatoo — Web Crawler Module
Sitemap, robots, recursive link discovery, form extraction, JS collection
"""

import re
import urllib.parse
from collections import deque
from typing import Set, List, Dict, Any, Optional


class Crawler:
    def __init__(
        self,
        target_url: str,
        rate_limiter,
        logger,
        reporter,
        session,
        max_depth: int = 3,
        max_pages: int = 100,
    ):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session
        self.max_depth  = max_depth
        self.max_pages  = max_pages
        self.parsed     = urllib.parse.urlparse(self.target_url)
        self.base_host  = self.parsed.netloc

        self.visited: Set[str]       = set()
        self.urls: List[str]         = []
        self.forms: List[Dict]       = []
        self.js_files: List[str]     = []
        self.params: Set[str]        = set()
        self.emails: Set[str]        = set()

    def run(self) -> Dict[str, Any]:
        self.log.module_start("Web Crawler")
        self._crawl(self.target_url, depth=0)
        self.log.success(f"Crawled {len(self.visited)} pages, found {len(self.forms)} forms, {len(self.js_files)} JS files")
        self.log.module_done("Web Crawler")
        return {
            "urls":     self.urls,
            "forms":    self.forms,
            "js_files": self.js_files,
            "params":   list(self.params),
            "emails":   list(self.emails),
        }

    def _crawl(self, url: str, depth: int):
        """BFS recursive crawler."""
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        url = self._normalize(url)
        if not url or url in self.visited:
            return
        if not self._is_same_host(url):
            return

        self.visited.add(url)
        self.urls.append(url)

        try:
            self.rl.wait(url)
            resp = self.session.get(url, timeout=10)
            self.rl.notify_response(url, resp.status_code)

            if resp.status_code != 200:
                return

            content_type = resp.headers.get("Content-Type", "")
            if "html" not in content_type and "javascript" not in content_type:
                return

            body = resp.text

            # Extract links
            links = self._extract_links(body, url)
            for link in links:
                self._crawl(link, depth + 1)

            # Extract forms
            forms = self._extract_forms(body, url)
            self.forms.extend(forms)

            # Extract JS files
            js = self._extract_js(body, url)
            for j in js:
                if j not in self.js_files:
                    self.js_files.append(j)

            # Extract query params
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                qp = urllib.parse.parse_qs(parsed.query)
                self.params.update(qp.keys())

            # Extract emails
            found_emails = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body)
            self.emails.update(found_emails)

            self.log.debug(f"Crawled: {url} [{len(links)} links]")

        except Exception as e:
            self.log.debug(f"Crawl error {url}: {e}")

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        links = []
        for pattern in [r'href=["\']([^"\']+)["\']', r'action=["\']([^"\']+)["\']']:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                href = match.group(1)
                full = urllib.parse.urljoin(base_url, href)
                full = self._normalize(full)
                if full and self._is_same_host(full):
                    links.append(full)
        return list(set(links))

    def _extract_forms(self, html: str, page_url: str) -> List[Dict]:
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            action_m  = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_m  = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action    = urllib.parse.urljoin(page_url, action_m.group(1)) if action_m else page_url
            method    = method_m.group(1).upper() if method_m else "GET"

            inputs = []
            for inp in re.finditer(r'<input[^>]*>', form_html, re.IGNORECASE):
                inp_html = inp.group(0)
                name_m   = re.search(r'name=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                type_m   = re.search(r'type=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                if name_m:
                    inputs.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                    })
                    self.params.add(name_m.group(1))

            # Textareas
            for ta in re.finditer(r'<textarea[^>]*name=["\']([^"\']*)["\']', form_html, re.IGNORECASE):
                inputs.append({"name": ta.group(1), "type": "textarea"})
                self.params.add(ta.group(1))

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "page":   page_url,
            })
        return forms

    def _extract_js(self, html: str, base_url: str) -> List[str]:
        js_files = []
        for match in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            src  = match.group(1)
            full = urllib.parse.urljoin(base_url, src)
            if self._is_same_host(full) or full.startswith("http"):
                js_files.append(full)
        return js_files

    def _normalize(self, url: str) -> Optional[str]:
        try:
            # Strip fragments
            url = url.split("#")[0].strip()
            if not url or url.startswith("mailto:") or url.startswith("javascript:"):
                return None
            # Make absolute
            if url.startswith("//"):
                url = self.parsed.scheme + ":" + url
            elif url.startswith("/"):
                url = f"{self.parsed.scheme}://{self.base_host}{url}"
            # Remove trailing slash
            return url.rstrip("/") or url
        except Exception:
            return None

    def _is_same_host(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.netloc == self.base_host or parsed.netloc == ""
        except Exception:
            return False
