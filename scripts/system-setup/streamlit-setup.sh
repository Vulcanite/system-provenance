#!/bin/bash

# About the script: This script sets up the Streamlit web application for eBPF forensic monitoring.
# It installs system dependencies (Python3, pip, graphviz), Python packages, and ensures config.json is available.

set -e  # Exit on error

echo "Checking Python version..."
if command -v python3.12 &> /dev/null; then
    echo "[+] Python 3.12 is already installed."
else
    echo "Python 3.12 not found. Installing from deadsnakes PPA..."
    sudo apt-get update
    sudo apt-get install -y software-properties-common
    sudo add-apt-repository -y ppa:deadsnakes/ppa
    sudo apt-get update
    echo "Installing Python 3.12..."
    sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
    echo "[+] Python 3.12 installed successfully."
fi

echo "Installing additional system dependencies..."
# FIX: Added graphviz as mentioned in description
sudo apt-get install -y python3-pip graphviz tshark

echo "Creating Python virtual environment..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
WEBAPP_DIR="$PROJECT_DIR/web"

cd "$WEBAPP_DIR"

if [ -d "venv" ]; then
    echo "[!] Virtual environment already exists, skipping creation."
else
    python3.12 -m venv venv
    echo "[+] Virtual environment created with Python 3.12."
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Setting up config.json..."
CONFIG_PATH="/var/config.json"
if [ -f "$CONFIG_PATH" ]; then
    echo "[+] Config file already exists at $CONFIG_PATH"
else
    echo "Creating config file at $CONFIG_PATH..."
    sudo mkdir -p /var/monitoring/events /var/monitoring/outputs
    # Ensure source config exists
    if [ -f "$PROJECT_DIR/config/config.json" ]; then
        sudo cp "$PROJECT_DIR/config/config.json" "$CONFIG_PATH"
        sudo chmod 644 "$CONFIG_PATH"
    else
        echo "[!] Warning: ../config/config.json not found. You must create $CONFIG_PATH manually."
    fi
fi

echo ""
echo "Setting up systemd service..."

# FIX: Dynamically generate the service file with absolute paths
# Systemd does not support variable expansion for WorkingDirectory/ExecStart
SERVICE_FILE="/lib/systemd/system/streamlit-webapp.service"

echo "Generating service file at $SERVICE_FILE..."
sudo tee "$SERVICE_FILE" > /dev/null <<EOF
[Unit]
Description=Forensice Web Application
After=network.target elasticsearch.service

[Service]
Type=simple
WorkingDirectory=$WEBAPP_DIR
ExecStart=$WEBAPP_DIR/venv/bin/python -m streamlit run webapp.py --server.port=8501 --server.address=0.0.0.0
Restart=always
RestartSec=5s
User=root
Group=root
Environment="PATH=$WEBAPP_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable streamlit-webapp.service
echo "[+] Systemd service installed. Start with: sudo systemctl start streamlit-webapp"

echo ""
echo "Access the web interface at: http://0.0.0.0:8501"
echo ""
echo "Important: Update Elasticsearch credentials in /var/config.json before starting."