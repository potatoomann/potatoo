"""
Potatoo — Expert AI Engine (No API Required)
Rule-based expert system that mimics senior pentester decision-making.
Orchestrates all modules in proper sequence with intelligent prioritization.
"""

import sys
import os
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.rate_limiter import RateLimiter
from core.reporter     import Reporter
from core.logger       import Logger

from modules.recon       import Recon
from modules.crawler     import Crawler
from modules.injections  import InjectionScanner
from modules.misconfig   import MisconfigScanner
from modules.auth_tester import AuthTester
from modules.secrets     import SecretDetector
from modules.js_analyzer import JSAnalyzer
from modules.vuln_scanner import VulnScanner


class PotatooEngine:
    """
    Senior Pentester Expert System.

    Decision logic:
    - Adjusts test priority based on detected tech stack
    - Chains findings across modules
    - Selects appropriate payloads based on context
    - Controls scan aggression based on --level
    """

    def __init__(self, config: dict):
        self.config      = config
        self.target      = config["target"]
        self.level       = config.get("level", 2)
        self.output      = config.get("output", "reports")
        self.verbose     = config.get("verbose", False)
        self.mode        = config.get("mode", "full")
        self.module_only = config.get("module", None)
        self.timeout     = config.get("timeout", 10)

        # Initialize core systems
        self.logger   = Logger(verbose=self.verbose)
        self.reporter = Reporter(self.target, output_path=self.output)
        self.rl       = self._configure_rate_limiter()
        self.session  = self._build_session()

        # State (populated during scan)
        self.tech_stack:  list = []
        self.crawl_data:  dict = {}
        self.recon_data:  dict = {}

    # ─── Session Setup ─────────────────────────────────────────────────────────
    def _build_session(self) -> requests.Session:
        import random
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        ]
        session = requests.Session()
        session.headers.update({
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,fr;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "DNT": "1",
        })
        session.verify = False
        # Allow redirects and accept cookies automatically
        session.max_redirects = 10
        return session


    # ─── Rate Limiter Config ───────────────────────────────────────────────────
    def _configure_rate_limiter(self) -> RateLimiter:
        level = self.level
        configs = {
            1: {"min_delay": 3.0,  "max_delay": 6.0,  "max_threads": 1, "rpm": 10},   # Very Stealthy
            2: {"min_delay": 1.0,  "max_delay": 3.0,  "max_threads": 2, "rpm": 30},   # Stealthy (Default)
            3: {"min_delay": 0.5,  "max_delay": 2.0,  "max_threads": 3, "rpm": 60},   # Balanced
            4: {"min_delay": 0.2,  "max_delay": 1.0,  "max_threads": 5, "rpm": 120},  # Aggressive
            5: {"min_delay": 0.1,  "max_delay": 0.5,  "max_threads": 8, "rpm": 300},  # Max Speed
        }
        cfg = configs.get(level, configs[2])
        return RateLimiter(
            min_delay=cfg["min_delay"],
            max_delay=cfg["max_delay"],
            max_threads=cfg["max_threads"],
            requests_per_minute=cfg["rpm"],
        )

    # ─── Main Orchestration ────────────────────────────────────────────────────
    def run(self):
        start_time = time.time()
        self.logger.info(f"Target: {self.target}")
        self.logger.info(f"Scan level: {self.level}/5  |  Mode: {self.mode}")
        self.logger.info(f"Rate limiting: {self.rl.min_delay:.1f}–{self.rl.max_delay:.1f}s delay")
        print()

        try:
            if self.module_only:
                self._run_single_module(self.module_only)
            elif self.mode == "recon":
                self._phase_recon()
            elif self.mode == "full":
                self._run_full_scan()
            else:
                self._run_full_scan()

        except KeyboardInterrupt:
            self.logger.warn("\nScan interrupted by user.")
        except Exception as e:
            self.logger.error(f"Engine error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
        finally:
            elapsed = time.time() - start_time
            self.reporter.finish()
            self._generate_reports(elapsed)

    def _run_full_scan(self):
        """Full sequential scan mimicking a senior pentester workflow."""

        # Phase 1: Recon (always first — determines strategy)
        self._phase_recon()

        # Phase 2: Crawl (map the attack surface)
        self._phase_crawl()

        # Phase 3: Adapt strategy based on discovered tech
        self._adapt_to_tech_stack()

        # Phase 4: Vulnerability Checks (parallel/sequential based on level)
        self._phase_misconfig()
        self._phase_secrets()
        self._phase_js_analysis()
        self._phase_auth()
        self._phase_injections()
        self._phase_vuln_scanner()

    # ─── Phases ────────────────────────────────────────────────────────────────
    def _phase_recon(self):
        recon = Recon(self.target, self.rl, self.logger, self.reporter, self.session)
        self.recon_data = recon.run()
        self.tech_stack = self.recon_data.get("technologies", [])

    def _phase_crawl(self):
        depth = {1: 2, 2: 3, 3: 4, 4: 5, 5: 6}.get(self.level, 3)
        pages = {1: 30, 2: 60, 3: 100, 4: 200, 5: 500}.get(self.level, 100)
        crawler = Crawler(
            self.target, self.rl, self.logger, self.reporter, self.session,
            max_depth=depth, max_pages=pages,
        )
        self.crawl_data = crawler.run()

    def _adapt_to_tech_stack(self):
        """AI decision: adapt checks based on detected tech."""
        tech = self.tech_stack
        self.logger.info(f"Adapting strategy to: {', '.join(tech) or 'unknown stack'}")

        # PHP-based → extra SQLi, LFI, RFI focus
        if "PHP" in tech or "WordPress" in tech:
            self.logger.info("→ PHP detected: prioritizing SQLi, LFI, WordPress-specific checks")

        # Java/Spring → SSTI, Actuator, deserialization focus
        if "Spring" in tech or "Java" in tech:
            self.logger.info("→ Java/Spring detected: prioritizing Spring Actuator, SSTI")

        # Node/Express → prototype pollution, XSS
        if "Express" in tech or "Next.js" in tech:
            self.logger.info("→ Node.js detected: prioritizing XSS, NoSQL injection")

        # React/Angular → DOM XSS, API endpoints
        if "React" in tech or "Angular" in tech or "Vue.js" in tech:
            self.logger.info("→ SPA detected: focusing on API endpoints and DOM XSS")

        # Cloudflare → WAF detected, use evasion payloads
        if "Cloudflare" in tech:
            self.logger.warn("→ Cloudflare WAF detected — some tests may be blocked")

    def _phase_misconfig(self):
        scanner = MisconfigScanner(self.target, self.rl, self.logger, self.reporter, self.session)
        scanner.run()

    def _phase_secrets(self):
        detector = SecretDetector(self.target, self.rl, self.logger, self.reporter, self.session)
        detector.run(
            urls=self.crawl_data.get("urls", []),
            js_files=self.crawl_data.get("js_files", []),
        )

    def _phase_js_analysis(self):
        analyzer = JSAnalyzer(self.target, self.rl, self.logger, self.reporter, self.session)
        result   = analyzer.run(js_files=self.crawl_data.get("js_files", []))
        # Add newly discovered endpoints to crawl data
        self.crawl_data["urls"] = list(set(
            self.crawl_data.get("urls", []) + result.get("endpoints", [])
        ))

    def _phase_auth(self):
        tester = AuthTester(self.target, self.rl, self.logger, self.reporter, self.session)
        tester.run(
            cookies=self.recon_data.get("cookies", []),
            forms=self.crawl_data.get("forms", []),
        )

    def _phase_injections(self):
        scanner = InjectionScanner(self.target, self.rl, self.logger, self.reporter, self.session)
        scanner.run(
            urls=self.crawl_data.get("urls", []),
            forms=self.crawl_data.get("forms", []),
            params=self.crawl_data.get("params", []),
        )

    def _phase_vuln_scanner(self):
        scanner = VulnScanner(self.target, self.rl, self.logger, self.reporter, self.session)
        scanner.run(
            subdomains=self.recon_data.get("subdomains", []),
            urls=self.crawl_data.get("urls", []),
        )

    def _run_single_module(self, module_name: str):
        """Run a specific module only."""
        modules = {
            "recon":      self._phase_recon,
            "crawl":      self._phase_crawl,
            "misconfig":  self._phase_misconfig,
            "secrets":    self._phase_secrets,
            "js":         self._phase_js_analysis,
            "auth":       self._phase_auth,
            "injections": self._phase_injections,
            "vuln":       self._phase_vuln_scanner,
        }
        fn = modules.get(module_name.lower())
        if fn:
            fn()
        else:
            self.logger.error(f"Unknown module: {module_name}. Available: {list(modules.keys())}")

    # ─── Report Generation ─────────────────────────────────────────────────────
    def _generate_reports(self, elapsed: float):
        self.logger.summary()

        json_path = self.reporter.save_json()
        html_path = self.reporter.save_html()

        stats = self.rl.get_stats()

        self.logger.info(f"Scan completed in {elapsed:.1f}s")
        self.logger.info(f"Total requests: {stats['total_requests']}")
        self.logger.info(f"Rate-limit backoffs: {stats['total_backoffs']}")
        self.logger.success(f"JSON report: {json_path}")
        self.logger.success(f"HTML report: {html_path}")
        print()
