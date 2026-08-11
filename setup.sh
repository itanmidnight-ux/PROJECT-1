#!/usr/bin/env bash
# CyberScope AI Security Platform — setup.sh
# Supports: Termux (Android) / Debian-Ubuntu / Arch / Alpine / Generic Linux
# Architectures: ARM64, x86_64, ARMv7

set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Uso: ./setup.sh"
    echo "Instala las dependencias necesarias para CyberScope en el sistema detectado."
    exit 0
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RED='\033[31m'; GRN='\033[32m'; YLW='\033[33m'; CYN='\033[36m'; NC='\033[0m'
ok()   { echo -e "${GRN}[✓]${NC} $*"; }
info() { echo -e "${CYN}[i]${NC} $*"; }
warn() { echo -e "${YLW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ── Detect environment ───────────────────────────────────────────────────────
ARCH=$(uname -m); OS=$(uname -s)

if [[ -n "${TERMUX_VERSION:-}" || -d "/data/data/com.termux" ]]; then
    ENV="termux"
elif [[ -f /etc/debian_version ]]; then ENV="debian"
elif [[ -f /etc/arch-release ]];   then ENV="arch"
elif [[ -f /etc/alpine-release ]]; then ENV="alpine"
else ENV="generic"; fi

echo ""
echo "  ██████╗██╗   ██╗██████╗ ███████╗██████╗"
echo "  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗"
echo "  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝"
echo "  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗"
echo "  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║"
echo "   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝"
echo ""
echo "  CyberScope AI Security Platform — Setup"
echo "  ==========================================="
info "Environment : $ENV ($ARCH / $OS)"
echo ""

# ── Python check ─────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then PY="python3"
elif command -v python &>/dev/null; then PY="python"
else die "Python not found. Install it first."; fi

PYVER_INT=$("$PY" -c 'import sys; print(sys.version_info.major * 10 + sys.version_info.minor)')
[[ $PYVER_INT -ge 39 ]] || die "Python 3.9+ required"
ok "Python $("$PY" --version 2>&1)"

# ── Install system packages ──────────────────────────────────────────────────
case "$ENV" in
  termux)
    info "Termux: installing Python packages directly (no venv needed)..."
    "$PY" -m pip install --quiet --upgrade pip
    "$PY" -m pip install --quiet -r "$ROOT/requirements.txt"
    ok "Packages installed (Termux)"
    ;;
  *)
    VENV="$ROOT/.venv"
    if [[ ! -d "$VENV" ]]; then
      info "Creating virtual environment..."
      "$PY" -m venv "$VENV"
    fi
    "$VENV/bin/pip" install --quiet --upgrade pip
    "$VENV/bin/pip" install --quiet -r "$ROOT/requirements.txt"
    ok "Packages installed (venv: $VENV)"
    ;;
esac

# ── Create runtime directories ───────────────────────────────────────────────
for d in logs reports database; do
  mkdir -p "$ROOT/$d"; ok "Directory: $ROOT/$d"
done

# ── Run tests ────────────────────────────────────────────────────────────────
info "Running test suite..."
cd "$ROOT"
if [[ "$ENV" == "termux" ]]; then
  "$PY" -m pytest tests/ -q --tb=short
else
  "$ROOT/.venv/bin/python" -m pytest tests/ -q --tb=short
fi
ok "All tests passed"

# ── Create runner script ─────────────────────────────────────────────────────
RUNNER="$ROOT/cyberscope"
if [[ "$ENV" == "termux" ]]; then
  cat > "$RUNNER" << EOF
#!/data/data/com.termux/files/usr/bin/env bash
exec python3 "$(dirname "\$0")/main.py" "\$@"
EOF
else
  cat > "$RUNNER" << EOF
#!/usr/bin/env bash
VENV="\$(dirname "\$0")/.venv"
if [[ -d "\$VENV" ]]; then
    exec "\$VENV/bin/python" "\$(dirname "\$0")/main.py" "\$@"
else
    exec python3 "\$(dirname "\$0")/main.py" "\$@"
fi
EOF
fi
chmod +x "$RUNNER"
ok "Runner: $ROOT/cyberscope"

echo ""
ok "Setup complete!"
echo ""
echo "  Usage:"
echo "    ./cyberscope              # interactive mode"
echo "    ./cyberscope --auto       # full auto-audit"
echo "    ./cyberscope --module wifi"
echo "    ./cyberscope --module telecom"
echo ""
