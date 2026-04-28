#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# ZeroGuardian XDR — Linux Installer
# Supports: Ubuntu 22.04, 24.04 · Debian 11, 12
#
# One command install:
#   curl -sSL https://raw.githubusercontent.com/Sanjay1911410125/Zeroguardian-XDR/main/install.sh | bash
# ─────────────────────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

GITHUB_URL="https://github.com/Sanjay1911410125/Zeroguardian-XDR.git"
INSTALL_DIR="/opt/zeroguardian-xdr"
PORT=5000

echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║           ZeroGuardian XDR — Linux Installer             ║"
echo "  ║     AI-Driven Zero-Day Threat Detection Platform         ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check root ────────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[Error]${NC} Please run as root: sudo bash install.sh"
  exit 1
fi

echo -e "${GREEN}[1/8]${NC} Updating system packages..."
apt-get update -qq

echo -e "${GREEN}[2/8]${NC} Installing system dependencies..."
apt-get install -y -qq \
  python3 python3-pip python3-venv python3-full \
  nmap curl wget git zip unzip \
  libpcap-dev net-tools sqlite3 \
  2>/dev/null
echo "  Dependencies installed ✅"

echo -e "${GREEN}[3/8]${NC} Downloading ZeroGuardian XDR from GitHub..."
if [ -d "$INSTALL_DIR" ]; then
  echo "  Updating existing installation..."
  cd "$INSTALL_DIR"
  git pull origin main 2>/dev/null || true
else
  git clone "$GITHUB_URL" "$INSTALL_DIR"
fi
echo "  Downloaded ✅"

echo -e "${GREEN}[4/8]${NC} Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
echo "  Virtual environment created ✅"

echo -e "${GREEN}[5/8]${NC} Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --quiet \
  flask \
  python-nmap \
  scapy \
  tensorflow-cpu \
  requests \
  reportlab \
  numpy \
  werkzeug
echo "  Python packages installed ✅"

echo -e "${GREEN}[6/8]${NC} Setting up database and AI model..."
cd "$INSTALL_DIR"

# Create required directories
mkdir -p models data reports logs

# Generate baseline training data if needed
if [ ! -f "data/normal_samples.jsonl" ]; then
  "$INSTALL_DIR/venv/bin/python3" -c "
import json, random, os
samples = [{'features': [round(random.uniform(3,8),1), round(random.uniform(10,100),1), round(random.uniform(2,6),1), round(random.uniform(1,4),1), round(random.uniform(0.5,15),2)]} for _ in range(150)]
with open('data/normal_samples.jsonl','w') as f:
    [f.write(json.dumps(s)+'\n') for s in samples]
print('  Baseline data generated: 150 samples')
"
fi

# Setup attack database
if [ -f "setup_attack_db.py" ]; then
  "$INSTALL_DIR/venv/bin/python3" setup_attack_db.py 2>/dev/null && \
    echo "  Attack database configured ✅" || true
fi

# Train autoencoder
if [ -f "train_autoencoder.py" ]; then
  "$INSTALL_DIR/venv/bin/python3" train_autoencoder.py 2>/dev/null && \
    echo "  AI model trained ✅" || \
    echo -e "  ${YELLOW}[Note]${NC} Run 'python3 train_autoencoder.py' manually to train model"
fi

# Create .env from example if not exists
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  cp .env.example .env
  # Generate a random secret key
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/REPLACE_WITH_YOUR_STRONG_SECRET_KEY/$SECRET/" .env
  echo "  Configuration file created ✅"
fi

echo -e "${GREEN}[7/8]${NC} Creating systemd service..."
cat > "/etc/systemd/system/zeroguardian.service" << EOF
[Unit]
Description=ZeroGuardian XDR Security Platform
Documentation=https://github.com/Sanjay1911410125/Zeroguardian-XDR
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 -m dashboard.app
Restart=always
RestartSec=10
Environment=PYTHONPATH=$INSTALL_DIR
StandardOutput=append:$INSTALL_DIR/logs/zeroguardian.log
StandardError=append:$INSTALL_DIR/logs/zeroguardian-error.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zeroguardian 2>/dev/null
systemctl start zeroguardian 2>/dev/null || true
echo "  Systemd service created and enabled ✅"

echo -e "${GREEN}[8/8]${NC} Creating zeroguardian command..."
cat > /usr/local/bin/zeroguardian << 'SCRIPT'
#!/bin/bash
case "$1" in
  start)   systemctl start zeroguardian   && echo "ZeroGuardian XDR started ✅" ;;
  stop)    systemctl stop zeroguardian    && echo "ZeroGuardian XDR stopped" ;;
  restart) systemctl restart zeroguardian && echo "ZeroGuardian XDR restarted ✅" ;;
  status)  systemctl status zeroguardian ;;
  logs)    journalctl -u zeroguardian -f ;;
  update)
    cd /opt/zeroguardian-xdr
    git pull origin main
    systemctl restart zeroguardian
    echo "ZeroGuardian XDR updated ✅"
    ;;
  open)
    IP=$(hostname -I | awk '{print $1}')
    xdg-open "http://$IP:5000" 2>/dev/null || echo "Open http://$IP:5000 in your browser"
    ;;
  *)
    echo ""
    echo "ZeroGuardian XDR — Commands"
    echo "  zeroguardian start    Start the service"
    echo "  zeroguardian stop     Stop the service"
    echo "  zeroguardian restart  Restart the service"
    echo "  zeroguardian status   Check service status"
    echo "  zeroguardian logs     View live logs"
    echo "  zeroguardian update   Update to latest version"
    echo "  zeroguardian open     Open dashboard in browser"
    echo ""
    ;;
esac
SCRIPT
chmod +x /usr/local/bin/zeroguardian

# ── Done ──────────────────────────────────────────────────────────────────────
LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║      ZeroGuardian XDR — Installation Complete! ✅        ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}Dashboard URL:${NC}     http://localhost:$PORT"
echo -e "  ${GREEN}LAN access:${NC}        http://$LOCAL_IP:$PORT"
echo -e "  ${GREEN}Auto-start:${NC}        Enabled on every boot"
echo -e "  ${GREEN}GitHub:${NC}            https://github.com/Sanjay1911410125/Zeroguardian-XDR"
echo ""
echo -e "  ${BOLD}Quick commands:${NC}"
echo -e "    zeroguardian start | stop | restart | status | logs | update"
echo ""
echo -e "  ${YELLOW}Next steps:${NC}"
echo -e "    1. Open http://$LOCAL_IP:$PORT in your browser"
echo -e "    2. Go to Settings → configure Telegram/Email alerts"
echo -e "    3. Run a vulnerability scan from the Vulnerabilities page"
echo -e "    4. Check Threat Feeds page to verify 22,000+ indicators loaded"
echo ""
