#!/usr/bin/env bash
# ============================================================
#  🥔 Potatoo Installer — Linux Setup Script
#  Installs Potatoo and makes `potatoo` available globally
# ============================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'
BROWN='\033[0;33m'

echo ""
echo -e "${BROWN}${BOLD}"
echo "  ██████╗  ██████╗ ████████╗ █████╗ ████████╗ ██████╗  ██████╗ "
echo "  ██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔═══██╗"
echo "  ██████╔╝██║   ██║   ██║   ███████║   ██║   ██║   ██║██║   ██║"
echo "  ██╔═══╝ ██║   ██║   ██║   ██╔══██║   ██║   ██║   ██║██║   ██║"
echo "  ██║     ╚██████╔╝   ██║   ██║  ██║   ██║   ╚██████╔╝╚██████╔╝"
echo "  ╚═╝      ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚═════╝ "
echo -e "${RESET}"
echo -e "  ${GREEN}🥔 Potatoo Installer${RESET}"
echo ""

# ─── Check Python ─────────────────────────────────────────────────────────────
echo -e "  ${CYAN}[*]${RESET} Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo -e "  ${RED}[✗]${RESET} Python 3 not found. Please install Python 3.8+"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  ${GREEN}[✓]${RESET} Python $PY_VER found"

# ─── Get install directory ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "  ${CYAN}[*]${RESET} Potatoo directory: ${SCRIPT_DIR}"

# ─── Install Python dependencies ──────────────────────────────────────────────
echo -e "  ${CYAN}[*]${RESET} Installing Python dependencies..."
if command -v pip3 &> /dev/null; then
    pip3 install -r "${SCRIPT_DIR}/requirements.txt" --quiet
elif command -v pip &> /dev/null; then
    pip install -r "${SCRIPT_DIR}/requirements.txt" --quiet
else
    echo -e "  ${RED}[✗]${RESET} pip not found. Install pip first: sudo apt install python3-pip"
    exit 1
fi
echo -e "  ${GREEN}[✓]${RESET} Dependencies installed"

# ─── Create launcher script ───────────────────────────────────────────────────
echo -e "  ${CYAN}[*]${RESET} Creating launcher..."
LAUNCHER="/usr/local/bin/potatoo"

cat > /tmp/potatoo_launcher << EOF
#!/usr/bin/env bash
exec python3 "${SCRIPT_DIR}/potatoo.py" "\$@"
EOF

# Try to install globally (requires sudo)
if [ -w /usr/local/bin ]; then
    cp /tmp/potatoo_launcher "$LAUNCHER"
    chmod +x "$LAUNCHER"
    echo -e "  ${GREEN}[✓]${RESET} Global command installed: /usr/local/bin/potatoo"
else
    echo -e "  ${YELLOW}[!]${RESET} Need sudo to install globally..."
    sudo cp /tmp/potatoo_launcher "$LAUNCHER"
    sudo chmod +x "$LAUNCHER"
    echo -e "  ${GREEN}[✓]${RESET} Global command installed: /usr/local/bin/potatoo"
fi

# ─── Also add local alias fallback ────────────────────────────────────────────
POTATOO_ALIAS="alias potatoo='python3 ${SCRIPT_DIR}/potatoo.py'"

for rc_file in ~/.bashrc ~/.zshrc ~/.bash_profile; do
    if [ -f "$rc_file" ]; then
        if ! grep -q "alias potatoo=" "$rc_file" 2>/dev/null; then
            echo "" >> "$rc_file"
            echo "# Potatoo Bug Bounty Tool" >> "$rc_file"
            echo "$POTATOO_ALIAS" >> "$rc_file"
        fi
    fi
done

# ─── Create reports directory ─────────────────────────────────────────────────
mkdir -p "${SCRIPT_DIR}/reports"
echo -e "  ${GREEN}[✓]${RESET} Reports directory ready: ${SCRIPT_DIR}/reports"

# ─── Test installation ────────────────────────────────────────────────────────
echo ""
echo -e "  ${CYAN}[*]${RESET} Testing installation..."
if python3 "${SCRIPT_DIR}/potatoo.py" --version 2>/dev/null; then
    echo ""
    echo -e "  ${GREEN}${BOLD}[✓] Potatoo installed successfully!${RESET}"
    echo ""
    echo -e "  ${YELLOW}Usage:${RESET}"
    echo -e "    ${BOLD}potatoo -u https://target.com${RESET}"
    echo -e "    ${BOLD}potatoo -u https://target.com --level 3${RESET}"
    echo -e "    ${BOLD}potatoo -u https://target.com --mode recon${RESET}"
    echo -e "    ${BOLD}potatoo --help${RESET}"
    echo ""
    echo -e "  ${RED}⚠  For authorized penetration testing ONLY${RESET}"
    echo ""
else
    echo -e "  ${RED}[✗]${RESET} Installation test failed. Check errors above."
    exit 1
fi
