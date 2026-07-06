"""
Potatoo — JavaScript Analyzer
Extract hidden endpoints, params, API keys from JS bundles
"""

import re
import urllib.parse
from typing import List, Dict, Set


# ─── Patterns ──────────────────────────────────────────────────────────────────
ENDPOINT_PATTERNS = [
    r'["\'](/(?:api|v\d|rest|graphql|admin|internal|private|backend)[^"\s\'<>]*)["\']',
    r'["\'](/[a-zA-Z0-9_\-/]+\.(?:php|asp|aspx|do|action|json|xml))["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    r'\$\.(?:get|post|ajax)\(\s*["\']([^"\']+)["\']',
    r'(?:url|URL|endpoint|Endpoint|path|Path)\s*[:=]\s*["\']([^"\']+)["\']',
    r'(?:baseURL|BASE_URL|API_URL|apiUrl)\s*[:=]\s*["\']([^"\']+)["\']',
    r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']',
]

PARAM_PATTERNS = [
    r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,30})=',
    r'["\']([a-zA-Z_][a-zA-Z0-9_]{2,30})["\']:\s*["\'][^"\']{0,100}["\']',
    r'params\[["\'](.*?)["\']\]',
    r'data\.\s*([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*=',
    r'FormData.*append\(["\']([^"\']+)["\']',
]

SOURCE_MAP_PATTERN = r'//[#@] sourceMappingURL=(.+\.map)'

SENSITIVE_JS_COMMENTS = [
    r'//\s*TODO.*(?:password|secret|key|token|hack|bypass|fixme)',
    r'/\*.*?(?:password|secret|key|token|backdoor|debug).*?\*/',
    r'console\.log\(["\'][^"\']*(?:password|token|secret|key)["\']',
]

GRAPHQL_PATTERNS = [
    r'query\s+\w+\s*\{',
    r'mutation\s+\w+\s*\{',
    r'subscription\s+\w+\s*\{',
    r'__schema',
    r'introspection',
]


class JSAnalyzer:
    def __init__(self, target_url, rate_limiter, logger, reporter, session):
        self.target_url = target_url.rstrip("/")
        self.rl         = rate_limiter
        self.log        = logger
        self.reporter   = reporter
        self.session    = session

    def run(self, js_files: List[str]) -> Dict:
        self.log.module_start("JavaScript Analysis")

        all_endpoints: Set[str] = set()
        all_params:    Set[str] = set()

        for js_url in js_files[:30]:
            try:
                self.rl.wait(js_url)
                resp = self.session.get(js_url, timeout=10)
                self.rl.notify_response(js_url, resp.status_code)
                if resp.status_code != 200:
                    continue

                js_text = resp.text

                # Extract endpoints
                eps = self._extract_endpoints(js_text, js_url)
                all_endpoints.update(eps)

                # Extract params
                params = self._extract_params(js_text)
                all_params.update(params)

                # Check for source maps
                self._check_source_maps(js_text, js_url)

                # Check sensitive comments
                self._check_sensitive_comments(js_text, js_url)

                # Check for GraphQL
                self._check_graphql(js_text, js_url)

                self.log.debug(f"JS analyzed: {js_url} → {len(eps)} endpoints")

            except Exception as e:
                self.log.debug(f"JS analysis error {js_url}: {e}")

        if all_endpoints:
            self.reporter.add_finding(
                title=f"Hidden Endpoints Discovered in JavaScript ({len(all_endpoints)})",
                severity="INFO",
                url=self.target_url,
                description=f"JavaScript analysis revealed {len(all_endpoints)} potentially hidden API endpoints.",
                evidence="\n".join(sorted(all_endpoints)[:30]),
                remediation="Review all discovered endpoints for proper access control.",
                module="js_analyzer",
                cvss=0.0,
            )
            self.log.success(f"Found {len(all_endpoints)} endpoints in JS files")

        self.log.module_done("JavaScript Analysis")
        return {"endpoints": list(all_endpoints), "params": list(all_params)}

    def _extract_endpoints(self, js_text: str, base_url: str) -> Set[str]:
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, js_text, re.IGNORECASE):
                ep = match.group(1).strip()
                if ep and not ep.startswith("//") and len(ep) > 2 and len(ep) < 200:
                    # Make absolute
                    if ep.startswith("/"):
                        parsed  = urllib.parse.urlparse(self.target_url)
                        ep_full = f"{parsed.scheme}://{parsed.netloc}{ep}"
                    elif ep.startswith("http"):
                        ep_full = ep
                    else:
                        ep_full = urllib.parse.urljoin(base_url, ep)
                    endpoints.add(ep_full)
        return endpoints

    def _extract_params(self, js_text: str) -> Set[str]:
        params = set()
        for pattern in PARAM_PATTERNS:
            for match in re.finditer(pattern, js_text):
                param = match.group(1).strip()
                if param and 2 <= len(param) <= 30 and param.isidentifier():
                    params.add(param)
        return params

    def _check_source_maps(self, js_text: str, js_url: str):
        matches = re.findall(SOURCE_MAP_PATTERN, js_text)
        for map_file in matches:
            map_url = urllib.parse.urljoin(js_url, map_file)
            try:
                self.rl.wait(map_url)
                resp = self.session.get(map_url, timeout=8)
                if resp.status_code == 200 and "sources" in resp.text:
                    self.reporter.add_finding(
                        title="JavaScript Source Map Exposed",
                        severity="HIGH",
                        url=map_url,
                        description="A JavaScript source map is publicly accessible — original source code can be reconstructed.",
                        evidence=f"Source map URL: {map_url}\nReferences source files in the response.",
                        remediation="Remove .map files from production deployment. Restrict access to source maps.",
                        module="js_analyzer",
                        cvss=7.5,
                    )
                    self.log.finding("HIGH", "Source map exposed", map_url)
            except Exception:
                pass

    def _check_sensitive_comments(self, js_text: str, js_url: str):
        for pattern in SENSITIVE_JS_COMMENTS:
            matches = re.findall(pattern, js_text, re.IGNORECASE | re.DOTALL)
            if matches:
                self.reporter.add_finding(
                    title="Sensitive Information in JavaScript Comments",
                    severity="MEDIUM",
                    url=js_url,
                    description="JavaScript file contains comments with potentially sensitive information.",
                    evidence="\n".join(str(m)[:200] for m in matches[:3]),
                    remediation="Remove sensitive comments from production JavaScript. Minify and strip comments.",
                    module="js_analyzer",
                    cvss=5.3,
                )
                self.log.finding("MEDIUM", "Sensitive JS comments", js_url)
                break

    def _check_graphql(self, js_text: str, js_url: str):
        graphql_hits = sum(1 for p in GRAPHQL_PATTERNS if re.search(p, js_text, re.IGNORECASE))
        if graphql_hits >= 2:
            # Try to find GraphQL endpoint
            graphql_endpoints = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
            for ep in graphql_endpoints:
                url = self.target_url + ep
                try:
                    self.rl.wait(url)
                    # Try introspection
                    introspection = '{"query":"{__schema{queryType{name}}}"}'
                    resp = self.session.post(
                        url,
                        data=introspection,
                        headers={"Content-Type": "application/json"},
                        timeout=8,
                    )
                    if resp.status_code == 200 and "__schema" in resp.text:
                        self.reporter.add_finding(
                            title="GraphQL Introspection Enabled",
                            severity="MEDIUM",
                            url=url,
                            description="GraphQL introspection is enabled — the full API schema can be dumped by attackers.",
                            evidence=f"Introspection query returned schema data at: {url}",
                            remediation="Disable introspection in production. Implement query depth limiting and field restrictions.",
                            module="js_analyzer",
                            cvss=5.3,
                        )
                        self.log.finding("MEDIUM", "GraphQL introspection enabled", url)
                        break
                except Exception:
                    pass
