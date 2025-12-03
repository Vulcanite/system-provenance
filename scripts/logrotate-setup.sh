#!/bin/bash

echo "Setting up logrotate..."
sudo cp "$SCRIPT_DIR/system-provenance-logrotate" /etc/logrotate.d/system-provenance
sudo chmod 644 /etc/logrotate.d/ebpf-provenance
echo "Logrotate configuration installed"