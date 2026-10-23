#!/bin/bash
set -e

# Resolve the directory this script lives in (robust even after cd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "⚡ AEGIS — AI Pentest Agent Installer (macOS Apple Silicon primary)"
echo "======================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
info() { echo -e "${BLUE}→${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }

# Check macOS
if [[ "$(uname)" != "Darwin" ]]; then
    warn "This installer is tuned for macOS. Linux/Windows support is future work (use WSL on Windows)."
    # continue anyway for partial
fi

# Check Homebrew
if ! command -v brew &>/dev/null; then
    info "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi
ok "Homebrew ready"

# === Install pentest tools ===
echo ""
echo "Installing pentest tools..."
echo ""

BREW_TOOLS=(
    nmap
    naabu
    httpx
    katana
    nuclei
    gobuster
    nikto
    sqlmap
    hydra
    ffuf
    subfinder
    theharvester
    ssh-audit
    whois
    net-snmp
    samba
    ruby
)
# WhatWeb, dnsrecon, and enum4linux are pinned source tools managed by the
# in-app Diagnostics installer; do not ask Homebrew for nonexistent formulas.

for tool in "${BREW_TOOLS[@]}"; do
    if brew list "$tool" &>/dev/null 2>&1; then
        ok "$tool (already installed)"
    else
        info "Installing $tool..."
        brew install "$tool" && ok "$tool" || warn "$tool (failed — Diagnostics will show a manual recovery command)"
    fi
done

if command -v nuclei &>/dev/null; then
    info "Updating the official Nuclei template set..."
    nuclei -update-templates || warn "Nuclei templates were not updated — retry from Diagnostics"
fi

# === Wordlists ===
echo ""
echo "Setting up wordlists..."
WORDLIST_DIR="$HOME/.aegis/wordlists"
mkdir -p "$WORDLIST_DIR"

SECLISTS_COMMIT="8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c"
ensure_wordlist() {
    local name="$1"
    local source_path="$2"
    local expected="$3"
    local destination="$WORDLIST_DIR/$name"
    local actual=""
    if [ -f "$destination" ]; then
        actual="$(shasum -a 256 "$destination" | awk '{print $1}')"
    fi
    if [ "$actual" != "$expected" ]; then
        info "Downloading pinned $name..."
        curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/$SECLISTS_COMMIT/$source_path" -o "$destination"
        actual="$(shasum -a 256 "$destination" | awk '{print $1}')"
    fi
    if [ "$actual" != "$expected" ]; then
        fail "Checksum mismatch for $name"
        exit 1
    fi
    ok "$name"
}

ensure_wordlist "common.txt" "Discovery/Web-Content/common.txt" "47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
ensure_wordlist "directories.txt" "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt" "d7619fe257485f3be56316c888e7392b2a0b1d4fce3593d298e8ab604118eaa7"
ensure_wordlist "subdomains.txt" "Discovery/DNS/subdomains-top1million-5000.txt" "e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19"

# === Python dependencies ===
echo ""
echo "Setting up Python backend..."
PY_BIN="python3"
if command -v python3.12 &>/dev/null; then
    PY_BIN="python3.12"
elif command -v python3.11 &>/dev/null; then
    PY_BIN="python3.11"
fi

cd "$SCRIPT_DIR/backend"
if [ -d ".venv" ] && [ -f ".venv/bin/activate" ]; then
    info ".venv exists — will upgrade deps only (per 'do not recreate on iterations' guidance)"
    source .venv/bin/activate
    pip install -q -r requirements-dev.txt --upgrade
else
    info "Creating fresh .venv (one-time for project setup)"
    $PY_BIN -m venv .venv
    source .venv/bin/activate
    pip install -q -r requirements-dev.txt
fi
ok "Python dependencies installed (using $PY_BIN)"

# === Node.js / Frontend ===
echo ""
echo "Setting up frontend..."
if ! command -v node &>/dev/null; then
    info "Installing Node.js..."
    brew install node
fi

cd "$SCRIPT_DIR"
npm ci --silent
cd "$SCRIPT_DIR/frontend"
npm ci --silent
npm run build --silent 2>/dev/null || warn "Frontend build — run 'npm run build' manually if needed"
ok "Frontend ready"

# === LM Studio hint ===
echo ""
if command -v lms &>/dev/null || [ -x "$HOME/.lmstudio/bin/lms" ]; then
    ok "lms CLI detected (LM Studio)"
else
    warn "lms CLI not found — install LM Studio from lmstudio.ai. AEGIS selects and exclusively loads your chosen downloaded model when a scan starts."
fi

# === Done ===
echo ""
echo "======================================"
echo -e "${GREEN}⚡ AEGIS installed successfully!${NC}"
echo ""
echo "To start (dev):"
echo "  cd \"$SCRIPT_DIR\""
echo "  # ensure the LM Studio local server is running; choose a downloaded model in AEGIS"
echo "  chmod +x start.sh && ./start.sh"
echo ""
echo "Or for single-port prod-like:"
echo "  cd backend && source .venv/bin/activate && python main.py"
echo "  (after: cd frontend && npm run build)"
echo "Then open http://localhost:8000"
echo "======================================"
