"""
Potatoo - ASCII Art Terminal Logo
"""

VERSION = "1.0.0"
AUTHOR  = "Potatoo Bug Bounty AI"

# ANSI color codes
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    ORANGE  = "\033[38;5;208m"
    BROWN   = "\033[38;5;130m"
    BG_BLACK = "\033[40m"

LOGO = f"""
{Colors.BROWN}{Colors.BOLD}
  ██████╗  ██████╗ ████████╗ █████╗ ████████╗ ██████╗  ██████╗ 
  ██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗
  ██████╔╝██║   ██║   ██║   ███████║   ██║   ██║   ██║██║   ██║
  ██╔═══╝ ██║   ██║   ██║   ██╔══██║   ██║   ██║   ██║██║   ██║
  ██║     ╚██████╔╝   ██║   ██║  ██║   ██║   ╚██████╔╝╚██████╔╝
  ╚═╝      ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ 
{Colors.RESET}"""

SUBTITLE = f"""  {Colors.GREEN}┌────────────────────────────────────────────────────────────┐{Colors.RESET}
  {Colors.GREEN}│{Colors.RESET}  {Colors.ORANGE}🥔{Colors.RESET}  {Colors.YELLOW}{Colors.BOLD}Automated Bug Bounty AI  —  Senior Pentester Level{Colors.RESET}  {Colors.ORANGE}🔐{Colors.RESET}  {Colors.GREEN}│{Colors.RESET}
  {Colors.GREEN}│{Colors.RESET}  {Colors.DIM}No APIs · Rate-Limited · OWASP Top 10 · Auto-Reporting{Colors.RESET}   {Colors.GREEN}│{Colors.RESET}
  {Colors.GREEN}└────────────────────────────────────────────────────────────┘{Colors.RESET}
  {Colors.DIM}v{VERSION}  |  {AUTHOR}  |  For authorized testing ONLY{Colors.RESET}
"""

MINI_POTATO = f"""
  {Colors.BROWN}     ██████    {Colors.RESET}
  {Colors.BROWN}   ██{Colors.YELLOW}░░░░{Colors.BROWN}██  {Colors.RESET}  {Colors.WHITE}{Colors.BOLD}POTATOO{Colors.RESET} {Colors.DIM}v{VERSION}{Colors.RESET}
  {Colors.BROWN}  ██{Colors.YELLOW}░{Colors.WHITE}◉{Colors.YELLOW}░{Colors.WHITE}◉{Colors.YELLOW}░{Colors.BROWN}██ {Colors.RESET}  {Colors.GREEN}Bug Bounty AI{Colors.RESET}
  {Colors.BROWN}  ██{Colors.YELLOW}░░{Colors.RED}▼{Colors.YELLOW}░░{Colors.BROWN}██ {Colors.RESET}
  {Colors.BROWN}   ████████  {Colors.RESET}
"""

def print_banner():
    """Print the full Potatoo banner."""
    print(LOGO)
    print(SUBTITLE)

def print_mini_banner():
    """Print a compact banner."""
    print(MINI_POTATO)

def print_section(title: str):
    """Print a styled section header."""
    width = 64
    pad = (width - len(title) - 2) // 2
    print(f"\n{Colors.GREEN}{'═' * width}{Colors.RESET}")
    print(f"{Colors.GREEN}║{Colors.RESET}{' ' * pad}{Colors.YELLOW}{Colors.BOLD} {title} {Colors.RESET}{' ' * pad}{Colors.GREEN}║{Colors.RESET}")
    print(f"{Colors.GREEN}{'═' * width}{Colors.RESET}\n")

def print_finding(severity: str, title: str, detail: str = ""):
    """Print a color-coded finding."""
    icons = {
        "CRITICAL": f"{Colors.RED}🔴 [CRITICAL]{Colors.RESET}",
        "HIGH":     f"{Colors.ORANGE}🟠 [HIGH]{Colors.RESET}",
        "MEDIUM":   f"{Colors.YELLOW}🟡 [MEDIUM]{Colors.RESET}",
        "LOW":      f"{Colors.GREEN}🟢 [LOW]{Colors.RESET}",
        "INFO":     f"{Colors.CYAN}🔵 [INFO]{Colors.RESET}",
    }
    icon = icons.get(severity.upper(), f"{Colors.WHITE}[?]{Colors.RESET}")
    print(f"  {icon} {Colors.WHITE}{Colors.BOLD}{title}{Colors.RESET}")
    if detail:
        print(f"       {Colors.DIM}{detail}{Colors.RESET}")

def print_status(msg: str, status: str = "RUN"):
    """Print a status line."""
    colors_map = {
        "RUN":  Colors.CYAN,
        "OK":   Colors.GREEN,
        "FAIL": Colors.RED,
        "WARN": Colors.YELLOW,
        "SKIP": Colors.DIM,
    }
    c = colors_map.get(status, Colors.WHITE)
    print(f"  {c}[{status}]{Colors.RESET} {msg}")

if __name__ == "__main__":
    print_banner()
