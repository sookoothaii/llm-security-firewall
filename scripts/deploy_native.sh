#!/bin/bash
# Native Deployment Script (NO DOCKER)
# =====================================
#
# Deploys LLM Firewall and detector services as native Python services.
# Uses systemd or supervisor for process management.
#
# Creator: HAK_GAL (Joerg Bollwahn)
# Date: 2025-12-07
# License: MIT

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== LLM Firewall Native Deployment ==="
echo "Project root: $PROJECT_ROOT"

# Configuration
ENVIRONMENT=${1:-production}
VENV_PATH="${PROJECT_ROOT}/venv"
SERVICES_DIR="${PROJECT_ROOT}/services"
LOGS_DIR="${PROJECT_ROOT}/logs"
PID_DIR="${PROJECT_ROOT}/pids"

# Create directories
mkdir -p "$SERVICES_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$PID_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8+"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_PATH" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_PATH"
fi

# Activate virtual environment
source "$VENV_PATH/bin/activate"

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r "${PROJECT_ROOT}/requirements.txt"
pip install -r "${PROJECT_ROOT}/detectors/code_intent_service/requirements.txt"
pip install -r "${PROJECT_ROOT}/detectors/persuasion_service/requirements.txt"

# Create systemd service files (if running as root)
if [ "$EUID" -eq 0 ]; then
    echo "Creating systemd service files..."
    
    # Firewall service
    cat > /etc/systemd/system/llm-firewall.service <<EOF
[Unit]
Description=LLM Security Firewall
After=network.target

[Service]
Type=simple
User=${SUDO_USER:-$USER}
WorkingDirectory=${PROJECT_ROOT}
Environment="PATH=${VENV_PATH}/bin"
ExecStart=${VENV_PATH}/bin/python -m llm_firewall.server
Restart=always
RestartSec=10
StandardOutput=append:${LOGS_DIR}/firewall.log
StandardError=append:${LOGS_DIR}/firewall.error.log

[Install]
WantedBy=multi-user.target
EOF

    # Code Intent Detector service
    cat > /etc/systemd/system/code-intent-detector.service <<EOF
[Unit]
Description=Code Intent Detector Service
After=network.target

[Service]
Type=simple
User=${SUDO_USER:-$USER}
WorkingDirectory=${PROJECT_ROOT}/detectors/code_intent_service
Environment="PATH=${VENV_PATH}/bin"
ExecStart=${VENV_PATH}/bin/uvicorn main:app --host 0.0.0.0 --port 8001
Restart=always
RestartSec=10
StandardOutput=append:${LOGS_DIR}/code_intent.log
StandardError=append:${LOGS_DIR}/code_intent.error.log

[Install]
WantedBy=multi-user.target
EOF

    # Persuasion Detector service
    cat > /etc/systemd/system/persuasion-detector.service <<EOF
[Unit]
Description=Persuasion/Misinfo Detector Service
After=network.target

[Service]
Type=simple
User=${SUDO_USER:-$USER}
WorkingDirectory=${PROJECT_ROOT}/detectors/persuasion_service
Environment="PATH=${VENV_PATH}/bin"
ExecStart=${VENV_PATH}/bin/uvicorn main:app --host 0.0.0.0 --port 8002
Restart=always
RestartSec=10
StandardOutput=append:${LOGS_DIR}/persuasion.log
StandardError=append:${LOGS_DIR}/persuasion.error.log

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload
    
    echo "✅ Systemd services created"
    echo ""
    echo "To start services:"
    echo "  sudo systemctl start llm-firewall"
    echo "  sudo systemctl start code-intent-detector"
    echo "  sudo systemctl start persuasion-detector"
    echo ""
    echo "To enable on boot:"
    echo "  sudo systemctl enable llm-firewall"
    echo "  sudo systemctl enable code-intent-detector"
    echo "  sudo systemctl enable persuasion-detector"
    
else
    # Non-root: Use supervisor or manual scripts
    echo "⚠️  Not running as root. Creating supervisor config and manual start scripts..."
    
    # Supervisor config
    cat > "${PROJECT_ROOT}/supervisor.conf" <<EOF
[program:llm-firewall]
command=${VENV_PATH}/bin/python -m llm_firewall.server
directory=${PROJECT_ROOT}
autostart=true
autorestart=true
stderr_logfile=${LOGS_DIR}/firewall.error.log
stdout_logfile=${LOGS_DIR}/firewall.log
user=${USER}

[program:code-intent-detector]
command=${VENV_PATH}/bin/uvicorn main:app --host 0.0.0.0 --port 8001
directory=${PROJECT_ROOT}/detectors/code_intent_service
autostart=true
autorestart=true
stderr_logfile=${LOGS_DIR}/code_intent.error.log
stdout_logfile=${LOGS_DIR}/code_intent.log
user=${USER}

[program:persuasion-detector]
command=${VENV_PATH}/bin/uvicorn main:app --host 0.0.0.0 --port 8002
directory=${PROJECT_ROOT}/detectors/persuasion_service
autostart=true
autorestart=true
stderr_logfile=${LOGS_DIR}/persuasion.error.log
stdout_logfile=${LOGS_DIR}/persuasion.log
user=${USER}
EOF

    # Manual start scripts
    cat > "${PROJECT_ROOT}/start_services.sh" <<'EOFSCRIPT'
#!/bin/bash
# Manual service start script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PATH="${SCRIPT_DIR}/venv"
LOGS_DIR="${SCRIPT_DIR}/logs"

source "${VENV_PATH}/bin/activate"

# Start services in background
nohup python -m llm_firewall.server > "${LOGS_DIR}/firewall.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/pids/firewall.pid"

cd "${SCRIPT_DIR}/detectors/code_intent_service"
nohup uvicorn main:app --host 0.0.0.0 --port 8001 > "${LOGS_DIR}/code_intent.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/pids/code_intent.pid"

cd "${SCRIPT_DIR}/detectors/persuasion_service"
nohup uvicorn main:app --host 0.0.0.0 --port 8002 > "${LOGS_DIR}/persuasion.log" 2>&1 &
echo $! > "${SCRIPT_DIR}/pids/persuasion.pid"

echo "Services started. PIDs:"
cat "${SCRIPT_DIR}/pids"/*.pid
EOFSCRIPT

    chmod +x "${PROJECT_ROOT}/start_services.sh"
    
    echo "✅ Supervisor config and start scripts created"
    echo ""
    echo "To start with supervisor:"
    echo "  supervisord -c ${PROJECT_ROOT}/supervisor.conf"
    echo ""
    echo "To start manually:"
    echo "  ${PROJECT_ROOT}/start_services.sh"
fi

echo ""
echo "=== Deployment Complete ==="
echo "Logs: ${LOGS_DIR}"
echo "PIDs: ${PID_DIR}"
