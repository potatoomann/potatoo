#!/usr/bin/env python3
"""
🥔 Potatoo — Automated Bug Bounty AI Tool
Senior Pentester Intelligence, No APIs, Rate-Limited

Usage:
  potatoo -u https://target.com
  potatoo -u https://target.com --level 3
  potatoo -u https://target.com --mode recon
  potatoo -u https://target.com --module injections
  potatoo -u https://target.com --output ~/reports/my_scan
"""

import sys
import os
import argparse

# Resolve paths
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from logo import print_banner, Colors, VERSION


def parse_args():
    parser = argparse.ArgumentParser(
        prog="potatoo",
        description="🥔 Potatoo — Automated Bug Bounty AI | Senior Pentester Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  potatoo -u https://example.com
  potatoo -u https://example.com --level 3
  potatoo -u https://example.com --mode recon
  potatoo -u https://example.com --module injections
  potatoo -u https://example.com --output ~/reports/scan1

Scan Levels:
  1 = Very Stealthy  (3–6s delay, 1 thread,  ~10 req/min)
  2 = Stealthy       (1–3s delay, 2 threads, ~30 req/min)  [default]
  3 = Balanced       (0.5–2s,    3 threads, ~60 req/min)
  4 = Aggressive     (0.2–1s,    5 threads, ~120 req/min)
  5 = Maximum        (0.1–0.5s,  8 threads, ~300 req/min)

Modules:
  recon, crawl, misconfig, secrets, js, auth, injections, vuln

  ⚠️  For authorized penetration testing ONLY.
        """,
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        metavar="URL",
        help="Target URL (e.g. https://example.com)",
    )
    parser.add_argument(
        "--level",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=2,
        metavar="LEVEL",
        help="Scan aggression level 1–5 (default: 2 = Stealthy)",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "recon"],
        default="full",
        metavar="MODE",
        help="Scan mode: full (default) or recon only",
    )
    parser.add_argument(
        "--module",
        metavar="MODULE",
        help="Run a single module: recon|crawl|misconfig|secrets|js|auth|injections|vuln",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        default="reports",
        help="Output directory for reports (default: ./reports)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip the ASCII banner",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Potatoo v{VERSION}",
    )
    return parser.parse_args()


def validate_url(url: str) -> str:
    """Ensure URL has a scheme."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def print_legal_notice():
    print(f"""  {Colors.RED}{Colors.BOLD}⚠  LEGAL NOTICE{Colors.RESET}
  {Colors.YELLOW}This tool is for authorized penetration testing and bug bounty programs ONLY.
  Scanning systems without explicit permission is illegal.
  By using Potatoo you accept full responsibility for your actions.{Colors.RESET}
""")


def main():
    args = parse_args()

    if not args.no_banner:
        print_banner()
        print_legal_notice()

    # Validate target
    target = validate_url(args.url)

    # Confirm if not verbose (safety check)
    if not args.verbose:
        try:
            confirm = input(
                f"  {Colors.YELLOW}Do you have permission to scan {Colors.BOLD}{target}{Colors.RESET}"
                f"{Colors.YELLOW}? [y/N]{Colors.RESET} "
            ).strip().lower()
            if confirm not in ("y", "yes"):
                print(f"  {Colors.RED}Scan aborted.{Colors.RESET}")
                sys.exit(0)
        except KeyboardInterrupt:
            print(f"\n  {Colors.RED}Scan aborted.{Colors.RESET}")
            sys.exit(0)
        print()

    # Import and run engine
    try:
        from core.engine import PotatooEngine
    except ImportError as e:
        print(f"  {Colors.RED}Error importing engine: {e}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Run: pip install -r requirements.txt{Colors.RESET}")
        sys.exit(1)

    config = {
        "target":  target,
        "level":   args.level,
        "mode":    args.mode,
        "module":  args.module,
        "output":  os.path.abspath(args.output),
        "verbose": args.verbose,
    }

    engine = PotatooEngine(config)
    engine.run()


if __name__ == "__main__":
    main()
