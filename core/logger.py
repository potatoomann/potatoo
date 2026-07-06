"""
Potatoo Core — Terminal Logger
"""

import sys
import datetime
from logo import Colors


class Logger:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._findings_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def _ts(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def info(self, msg: str):
        print(f"  {Colors.CYAN}[{self._ts()}]{Colors.RESET} {msg}")

    def success(self, msg: str):
        print(f"  {Colors.GREEN}[{self._ts()}] ✓{Colors.RESET} {msg}")

    def warn(self, msg: str):
        print(f"  {Colors.YELLOW}[{self._ts()}] ⚠{Colors.RESET} {msg}")

    def error(self, msg: str):
        print(f"  {Colors.RED}[{self._ts()}] ✗{Colors.RESET} {msg}", file=sys.stderr)

    def debug(self, msg: str):
        if self.verbose:
            print(f"  {Colors.DIM}[{self._ts()}] DEBUG: {msg}{Colors.RESET}")

    def finding(self, severity: str, title: str, url: str = "", detail: str = "", evidence: str = ""):
        sev = severity.upper()
        self._findings_count[sev] = self._findings_count.get(sev, 0) + 1

        icons = {
            "CRITICAL": f"{Colors.RED}{Colors.BOLD}🔴 CRITICAL{Colors.RESET}",
            "HIGH":     f"{Colors.ORANGE}🟠 HIGH{Colors.RESET}",
            "MEDIUM":   f"{Colors.YELLOW}🟡 MEDIUM{Colors.RESET}",
            "LOW":      f"{Colors.GREEN}🟢 LOW{Colors.RESET}",
            "INFO":     f"{Colors.CYAN}🔵 INFO{Colors.RESET}",
        }
        icon = icons.get(sev, f"{Colors.WHITE}[?]{Colors.RESET}")

        print(f"\n  ┌─ {icon} ─ {Colors.WHITE}{Colors.BOLD}{title}{Colors.RESET}")
        if url:
            print(f"  │  {Colors.DIM}URL:{Colors.RESET} {Colors.CYAN}{url}{Colors.RESET}")
        if detail:
            print(f"  │  {Colors.DIM}Detail:{Colors.RESET} {detail}")
        if evidence:
            print(f"  │  {Colors.DIM}Evidence:{Colors.RESET} {Colors.YELLOW}{evidence[:200]}{Colors.RESET}")
        print(f"  └{'─' * 60}")

    def module_start(self, module_name: str):
        print(f"\n  {Colors.MAGENTA}{'▶' * 3} {Colors.BOLD}{module_name.upper()}{Colors.RESET} {Colors.MAGENTA}{'◀' * 3}{Colors.RESET}")

    def module_done(self, module_name: str):
        print(f"  {Colors.GREEN}✓ {module_name} complete{Colors.RESET}")

    def summary(self):
        """Print findings summary."""
        print(f"\n  {Colors.GREEN}{'═' * 60}{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.WHITE}  SCAN SUMMARY{Colors.RESET}")
        print(f"  {Colors.GREEN}{'═' * 60}{Colors.RESET}")
        for sev, count in self._findings_count.items():
            if count > 0:
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}.get(sev, "⚪")
                print(f"  {icon}  {sev:<10} {Colors.BOLD}{count:>4} finding(s){Colors.RESET}")
        total = sum(self._findings_count.values())
        print(f"  {Colors.GREEN}{'─' * 60}{Colors.RESET}")
        print(f"  {'TOTAL':<15} {Colors.BOLD}{Colors.WHITE}{total:>4} finding(s){Colors.RESET}")
        print(f"  {Colors.GREEN}{'═' * 60}{Colors.RESET}\n")

    def progress(self, current: int, total: int, label: str = ""):
        bar_len = 30
        filled = int(bar_len * current / max(total, 1))
        bar = f"{Colors.GREEN}{'█' * filled}{Colors.DIM}{'░' * (bar_len - filled)}{Colors.RESET}"
        pct = int(100 * current / max(total, 1))
        print(f"\r  [{bar}] {pct:3d}% {Colors.DIM}{label}{Colors.RESET}  ", end="", flush=True)
        if current >= total:
            print()
