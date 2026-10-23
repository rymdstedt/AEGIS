#!/bin/bash
# Build the Python backend into a standalone executable using PyInstaller.
# Run from project root: npm run build:server
# Cross-platform: macOS (for .dmg) and Ubuntu/Linux (for AppImage/deb/tar.gz).
# Ubuntu example setup:
#   sudo apt update && sudo apt install -y python3-venv python3-pip build-essential
#   python3 -m venv .venv
#   source .venv/bin/activate
#   pip install -r requirements.txt
#   npm run build:ui   # can be done on any machine
#   npm run build:server
#   npm run dist:linux
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

BUILD_ID="${BUILD_ID:-$(date +%Y%m%d-%H%M)}"
echo "==> Building standalone AEGIS backend (PyInstaller)..."
echo "    Build ID: $BUILD_ID"
echo "    Detected platform: $(uname -s) $(uname -m)"

cd "$SCRIPT_DIR/backend"

if [ ! -d ".venv" ]; then
    echo "ERROR: backend/.venv not found. Run the venv setup first (see install.sh or create manually on your platform)."
    exit 1
fi

source .venv/bin/activate

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# PyInstaller is pinned in requirements.txt. Never resolve an unpinned build
# dependency during a release build.
python -c "import PyInstaller" 2>/dev/null || {
    echo "ERROR: pinned build dependencies are missing. Run: pip install -r backend/requirements.txt"
    exit 1
}

# Make sure frontend is built (the data we embed)
if [ ! -d "$SCRIPT_DIR/frontend/dist" ]; then
    echo "Frontend dist not found — building it..."
    (cd "$SCRIPT_DIR/frontend" && npm run build)
fi

# --- Bundle wordlists so the dmg is more self-contained (no network on first run on clean Mac) ---
echo "==> Preparing bundled wordlists (for clean install self-containment)..."
mkdir -p dist/wordlists
for wl in common.txt directories.txt subdomains.txt; do
    url=""
    expected=""
    case "$wl" in
        common.txt)
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/common.txt"
            expected="47fb86ca6fb3f97e5491161581900d6d99851fb16764eacddf16aa85617c956a"
            ;;
        directories.txt)
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
            expected="d7619fe257485f3be56316c888e7392b2a0b1d4fce3593d298e8ab604118eaa7"
            ;;
        subdomains.txt)
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/8a52c0a7e6edaaf0378dd9e4446c3d8039e2ff4c/Discovery/DNS/subdomains-top1million-5000.txt"
            expected="e331367c140298cb179114fdeefa78f58f696219f0dec017a28bb79487cfcf19"
            ;;
    esac
    if [ ! -f "dist/wordlists/$wl" ]; then
        echo "    Downloading pinned $wl ..."
        curl -fsSL "$url" -o "dist/wordlists/$wl"
    fi
    actual=$(sha256_file "dist/wordlists/$wl")
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: checksum mismatch for wordlist $wl"
        exit 1
    fi
done

# --- Bundle portable versions of common Go-based tools (gobuster, ffuf, subfinder) ---
# This makes dirbusting, fuzzing and subdomain enum work on a brand new machine (macOS DMG *or* Ubuntu AppImage/deb)
# with zero `brew install` / `apt install` for the Go tools. Run the full build *on the target OS* so PyInstaller
# + these fetches produce native binaries for that platform.
echo "==> Preparing portable vendored tools (gobuster/ffuf/subfinder) for self-contained installs..."
mkdir -p dist/tools
pushd dist/tools >/dev/null

HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)

verify_binary() {
    name="$1"
    expected="$2"
    if [ ! -f "$name" ]; then
        echo "ERROR: required vendored tool is missing: $name"
        exit 1
    fi
    actual=$(sha256_file "$name")
    if [ "$actual" != "$expected" ]; then
        echo "ERROR: checksum mismatch for $name"
        echo "       expected $expected"
        echo "       actual   $actual"
        exit 1
    fi
}

if [ "$HOST_OS" = "Darwin" ] || [ "$HOST_OS" = "darwin" ]; then
    if [ "$HOST_ARCH" != "arm64" ]; then
        echo "ERROR: the macOS package currently targets arm64; refusing to bundle the wrong architecture"
        exit 1
    fi
    if [ ! -f gobuster ]; then
        echo "    Fetching gobuster..."
        curl -fsSL -o gobuster.tar.gz https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Darwin_arm64.tar.gz || true
        tar -xzf gobuster.tar.gz gobuster 2>/dev/null || true
        rm -f gobuster.tar.gz
        [ -f gobuster ] && chmod +x gobuster && echo "    ✓ gobuster vendored"
    fi

    if [ ! -f ffuf ]; then
        echo "    Fetching ffuf..."
        curl -fsSL -o ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_macOS_arm64.tar.gz || true
        tar -xzf ffuf.tar.gz ffuf 2>/dev/null || true
        rm -f ffuf.tar.gz
        [ -f ffuf ] && chmod +x ffuf && echo "    ✓ ffuf vendored"
    fi

    if [ ! -f subfinder ]; then
        echo "    Fetching subfinder..."
        curl -fsSL -o subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_macOS_arm64.zip || true
        unzip -o subfinder.zip subfinder 2>/dev/null || true
        rm -f subfinder.zip LICENSE* 2>/dev/null || true
        [ -f subfinder ] && chmod +x subfinder && echo "    ✓ subfinder vendored"
    fi
    verify_binary gobuster 8b44425f088dcd5d87f60cd16d31ef41a22031ccf55361690835175b2472160e
    verify_binary ffuf ce895e54e1f0500849fc24bc7d8c40ab457a822d430cb3ed386b8e9cc7cddb81
    verify_binary subfinder 50bec9f374fa9c1054e1e1dfdc5b7d3340b358bd3019a14c47f13079d2c1077e
elif [ "$HOST_OS" = "Linux" ] || [ "$HOST_OS" = "linux" ]; then
    # Linux (Ubuntu etc). Matches amd64 (x86_64) or arm64. Produces correct ELF binaries inside the AppImage/deb.
    if [ ! -f gobuster ]; then
        echo "    Fetching gobuster (linux)..."
        if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ]; then
            curl -fsSL -o gobuster.tar.gz https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz || true
        else
            curl -fsSL -o gobuster.tar.gz https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_arm64.tar.gz || true
        fi
        tar -xzf gobuster.tar.gz gobuster 2>/dev/null || true
        rm -f gobuster.tar.gz
        [ -f gobuster ] && chmod +x gobuster && echo "    ✓ gobuster vendored (linux)"
    fi

    if [ ! -f ffuf ]; then
        echo "    Fetching ffuf (linux)..."
        if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ]; then
            curl -fsSL -o ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz || true
        else
            curl -fsSL -o ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_arm64.tar.gz || true
        fi
        tar -xzf ffuf.tar.gz ffuf 2>/dev/null || true
        rm -f ffuf.tar.gz
        [ -f ffuf ] && chmod +x ffuf && echo "    ✓ ffuf vendored (linux)"
    fi

    if [ ! -f subfinder ]; then
        echo "    Fetching subfinder (linux)..."
        if [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "amd64" ]; then
            curl -fsSL -o subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_amd64.zip || true
        else
            curl -fsSL -o subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.14.0/subfinder_2.14.0_linux_arm64.zip || true
        fi
        unzip -o subfinder.zip subfinder 2>/dev/null || true
        rm -f subfinder.zip LICENSE* 2>/dev/null || true
        [ -f subfinder ] && chmod +x subfinder && echo "    ✓ subfinder vendored (linux)"
    fi
    if [ "$HOST_ARCH" = "x86_64" ] || [ "$HOST_ARCH" = "amd64" ]; then
        verify_binary gobuster bef069c4233495d8b83b1fa7bc856cdd3a5bcf0cb40056f806d7698002fc8bbf
        verify_binary ffuf b0183aeed13d3ccea5db79809ca4135b7561257406a0f5d6f982e0551abea4e7
        verify_binary subfinder 88e6b07d47afee46804db926f46bba99eadee74e0ccb32b2f792bfea62b9da0c
    elif [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ]; then
        verify_binary gobuster 198fc8f645bfac0b4101d27e9d98c23e617257d97e0a7025aeaaef321ca8626d
        verify_binary ffuf 63ef267bef305eba63d9234dfe1c486be2d48c72d63edc733937ed1014cfb70f
        verify_binary subfinder 776c010aaa70785dc1b28a9cd16ba53bf1c748bec76670c0648275919a68214a
    else
        echo "ERROR: unsupported Linux architecture: $HOST_ARCH"
        exit 1
    fi
else
    echo "    (Unknown host OS for vendored tools; skipping auto-fetch. Install gobuster/ffuf/subfinder manually if needed.)"
fi

popd >/dev/null

# --- Vendor sources for the git-only / non-brew pentest tools (whatweb, dnsrecon, enum4linux) ---
# These have no `brew install <name>` that works (whatweb -> suggests whatcable cask, dnsrecon -> dnsrobocert,
# enum4linux has zero formula). By baking the git sources into the DMG we make them "installed when you
# install the program". ensure_script_tools() + _find_managed_tool() at runtime place + detect them in
# ~/.aegis/tools so they do not appear in "missing_tools" and /api/install-tool never runs `brew install whatweb`.
# Their language runtime deps (ruby gems, pip reqs) are still one-time setup (visible via the Install button).
echo "==> Preparing vendored sources for non-brew tools (whatweb/dnsrecon/enum4linux) ..."
mkdir -p dist/tools-sources
pushd dist/tools-sources >/dev/null

prepare_source() {
    name="$1"
    repo="$2"
    commit="$3"
    entrypoint="$4"
    if [ ! -d "$name/.git" ]; then
        echo "    Fetching pinned $name source ..."
        mkdir -p "$name"
        git -C "$name" init -q
        git -C "$name" remote add origin "$repo"
        git -C "$name" fetch --depth 1 origin "$commit"
        git -C "$name" checkout -q --detach "$commit"
    fi
    actual=$(git -C "$name" rev-parse HEAD 2>/dev/null || true)
    if [ "$actual" != "$commit" ] || [ ! -f "$name/$entrypoint" ]; then
        echo "ERROR: $name source is missing or not at pinned commit $commit"
        exit 1
    fi
    chmod +x "$name/$entrypoint" 2>/dev/null || true
    echo "    ✓ $name source verified at $commit"
}

prepare_source whatweb https://github.com/urbanadventurer/WhatWeb.git d279d93042d034f3fd29d5a893d44ccc0595d3f8 whatweb
prepare_source dnsrecon https://github.com/darkoperator/dnsrecon.git d9633804a3035a2e44ad326b55fcf767819ab809 dnsrecon.py
prepare_source enum4linux https://github.com/CiscoCXSecurity/enum4linux.git e6fe887710f72ab4620580cb841eb29296e38211 enum4linux.pl

# WhatWeb's pinned release mutates a process-wide OpenSSL defaults hash that
# became frozen in Ruby 4. Apply our small compatibility patch reproducibly to
# fresh source fetches as well as incremental builds.
WHATWEB_PATCH="$SCRIPT_DIR/scripts/patches/whatweb-ruby4.patch"
if git -C whatweb apply --reverse --check "$WHATWEB_PATCH" >/dev/null 2>&1; then
    echo "    ✓ WhatWeb Ruby 4 compatibility patch already applied"
elif git -C whatweb apply --check "$WHATWEB_PATCH" >/dev/null 2>&1; then
    git -C whatweb apply "$WHATWEB_PATCH"
    echo "    ✓ Applied WhatWeb Ruby 4 compatibility patch"
else
    echo "ERROR: WhatWeb Ruby 4 compatibility patch no longer applies cleanly"
    exit 1
fi

popd >/dev/null

# Write build metadata so the running app can report exactly which build this is
cat > dist/build-info.json <<EOF
{
  "buildId": "$BUILD_ID",
  "buildDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "$(node -p "require('$SCRIPT_DIR/package.json').version" 2>/dev/null || echo '2.1.0')",
  "bundledWordlists": $(ls dist/wordlists/*.txt 2>/dev/null | wc -l | tr -d ' '),
  "bundledScriptSources": $(ls -d dist/tools-sources/*/ 2>/dev/null | wc -l | tr -d ' ')
}
EOF
echo "    Wrote dist/build-info.json for build $BUILD_ID"

echo "==> Running PyInstaller (onedir + embedded UI + wordlists + build-info)..."

# Keep generated specifications and work files out of the source tree.
mkdir -p build
rm -rf dist/aegis-server build/aegis-server.spec build/pyinstaller build/pyinstaller-config 2>/dev/null || true
export PYINSTALLER_CONFIG_DIR="$SCRIPT_DIR/backend/build/pyinstaller-config"

pyinstaller \
  --clean \
  --onedir \
  --name aegis-server \
  --add-data "$SCRIPT_DIR/frontend/dist:frontend/dist" \
  --add-data "$SCRIPT_DIR/backend/dist/wordlists:wordlists" \
  --add-data "$SCRIPT_DIR/backend/dist/tools:tools" \
  --add-data "$SCRIPT_DIR/backend/dist/tools-sources:tools-sources" \
  --add-data "$SCRIPT_DIR/backend/dist/build-info.json:." \
  --distpath dist \
  --specpath build \
  --workpath build/pyinstaller \
  --noconfirm \
  --log-level WARN \
  --noupx \
  server.py

# The binary ends up at backend/dist/aegis-server (single executable file on mac)
chmod +x dist/aegis-server

echo ""
echo "✓ Backend frozen successfully:"
ls -lh dist/aegis-server/aegis-server
echo ""
echo "  (This signed runtime directory will be bundled into the .app/.dmg (mac) or linux package (AppImage/deb) by electron-builder)"
echo "  It includes the FastAPI server + the built React UI assets + bundled wordlists."
