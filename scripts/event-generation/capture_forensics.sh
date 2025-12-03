#!/bin/bash
# Capture PCAP and audit logs while running activity scripts
# This simulates real-world forensic data collection

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=============================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================${NC}"
}

print_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[x]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (for PCAP capture and auditd)"
    echo "Usage: sudo $0 [duration_in_seconds]"
    exit 1
fi

# Configuration
DURATION=${1:-60}  # Default 60 seconds
OUTPUT_DIR="./forensic_captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$OUTPUT_DIR/capture_${TIMESTAMP}.pcap"
AUDIT_LOG="$OUTPUT_DIR/audit_${TIMESTAMP}.log"
ACTIVITY_SCRIPT="./generate_activity.sh"

# Network interface detection
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$INTERFACE" ]; then
    INTERFACE="eth0"  # Fallback
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

print_header "Forensic Data Capture Tool"
echo ""
print_info "Configuration:"
echo "  - Duration: ${DURATION} seconds"
echo "  - Network Interface: $INTERFACE"
echo "  - PCAP Output: $PCAP_FILE"
echo "  - Audit Log Output: $AUDIT_LOG"
echo "  - Activity Script: $ACTIVITY_SCRIPT"
echo ""

# Check dependencies
print_info "Checking dependencies..."

if ! command -v tcpdump &> /dev/null; then
    print_error "tcpdump not found. Install with: apt-get install tcpdump"
    exit 1
fi

# Check for audit tools
USE_AUDITD=0
USE_STRACE=0

if command -v auditctl &> /dev/null && systemctl is-active --quiet auditd 2>/dev/null; then
    # Test if audit actually works by checking kernel support
    if auditctl -l > /dev/null 2>&1; then
        print_info "Using auditd for syscall monitoring"
        USE_AUDITD=1

        # Check if kernel has audit enabled
        if [ ! -e /proc/sys/kernel/audit ]; then
            print_warn "Kernel audit support may be limited"
        fi
    else
        print_warn "auditd service is running but auditctl is not functional"
        print_warn "This may indicate kernel audit support is disabled"
        if command -v strace &> /dev/null; then
            print_info "Falling back to strace for syscall monitoring"
            USE_STRACE=1
        fi
    fi
elif command -v strace &> /dev/null; then
    print_info "auditd not available, using strace as fallback"
    USE_STRACE=1
else
    print_warn "Neither auditd nor strace available. Install one of them:"
    print_warn "  - auditd: apt-get install auditd"
    print_warn "  - strace: apt-get install strace"
    print_warn "Continuing without syscall logs..."
fi

if [ ! -f "$ACTIVITY_SCRIPT" ]; then
    print_error "Activity script not found: $ACTIVITY_SCRIPT"
    exit 1
fi

chmod +x "$ACTIVITY_SCRIPT"

echo ""
print_header "Starting Capture"
echo ""

# Function to cleanup on exit
cleanup() {
    print_info "Cleaning up..."

    # Stop PCAP capture
    if [ ! -z "$TCPDUMP_PID" ]; then
        kill $TCPDUMP_PID 2>/dev/null || true
        wait $TCPDUMP_PID 2>/dev/null || true
    fi

    # Clean up audit rules if we set them
    if [ $USE_AUDITD -eq 1 ]; then
        auditctl -D > /dev/null 2>&1 || true
    fi

    # Stop activity generation
    if [ ! -z "$ACTIVITY_PID" ]; then
        kill $ACTIVITY_PID 2>/dev/null || true
        wait $ACTIVITY_PID 2>/dev/null || true
    fi

    echo ""
    print_header "Capture Summary"
    echo ""

    if [ -f "$PCAP_FILE" ]; then
        PCAP_SIZE=$(du -h "$PCAP_FILE" | cut -f1)
        PACKET_COUNT=$(tcpdump -r "$PCAP_FILE" 2>/dev/null | wc -l || echo "0")
        print_info "PCAP File: $PCAP_FILE"
        echo "  - Size: $PCAP_SIZE"
        echo "  - Packets: $PACKET_COUNT"
        echo ""
    fi

    if [ -f "$AUDIT_LOG" ]; then
        AUDIT_SIZE=$(du -h "$AUDIT_LOG" | cut -f1)
        EVENT_COUNT=$(wc -l < "$AUDIT_LOG")
        print_info "Audit Log: $AUDIT_LOG"
        echo "  - Size: $AUDIT_SIZE"
        echo "  - Events: $EVENT_COUNT"

        # Check if JSON version exists
        JSON_AUDIT_LOG="${AUDIT_LOG%.log}.json"
        if [ -f "$JSON_AUDIT_LOG" ]; then
            JSON_SIZE=$(du -h "$JSON_AUDIT_LOG" | cut -f1)
            JSON_COUNT=$(wc -l < "$JSON_AUDIT_LOG")
            print_info "Audit Log (JSON): $JSON_AUDIT_LOG"
            echo "  - Size: $JSON_SIZE"
            echo "  - JSON Events: $JSON_COUNT"
        fi
        echo ""
    fi

    print_info "You can now upload these files to the Offline Analysis page:"
    echo "  1. Open the web interface"
    echo "  2. Navigate to 'Offline Analysis' tab"
    echo "  3. Upload $PCAP_FILE"

    # Recommend JSON file if available
    if [ -f "${AUDIT_LOG%.log}.json" ]; then
        echo "  4. Upload ${AUDIT_LOG%.log}.json (JSON format - recommended)"
    else
        echo "  4. Upload $AUDIT_LOG (raw format)"
    fi
    echo ""
}

trap cleanup EXIT INT TERM

# Start PCAP capture
print_info "Starting PCAP capture on interface $INTERFACE..."
tcpdump -i $INTERFACE -w "$PCAP_FILE" -s 65535 'tcp or udp' > /dev/null 2>&1 &
TCPDUMP_PID=$!
print_info "PCAP capture started (PID: $TCPDUMP_PID)"
sleep 2  # Wait for tcpdump to start

# Start syscall logging
if [ $USE_AUDITD -eq 1 ]; then
    print_info "Starting auditd logging..."

    # Save start timestamp for later filtering (use locale format for ausearch)
    AUDIT_START_TIME=$(date +'%x %X')
    AUDIT_START_EPOCH=$(date +%s)

    # Configure audit rules for syscalls we care about
    auditctl -D > /dev/null 2>&1 || true  # Clear existing rules

    # Add rules for network syscalls (with error checking)
    RULES_ADDED=0

    if auditctl -a exit,always -F arch=b64 -S connect -k network_connect 2>&1; then
        print_info "  ✓ Added 'connect' audit rule"
        RULES_ADDED=$((RULES_ADDED + 1))
    else
        print_warn "  ✗ Failed to add 'connect' audit rule"
    fi

    if auditctl -a exit,always -F arch=b64 -S bind -k network_bind 2>&1; then
        print_info "  ✓ Added 'bind' audit rule"
        RULES_ADDED=$((RULES_ADDED + 1))
    else
        print_warn "  ✗ Failed to add 'bind' audit rule"
    fi

    if auditctl -a exit,always -F arch=b64 -S socket -k network_socket 2>&1; then
        print_info "  ✓ Added 'socket' audit rule"
        RULES_ADDED=$((RULES_ADDED + 1))
    else
        print_warn "  ✗ Failed to add 'socket' audit rule"
    fi

    # Add rules for file operations
    if auditctl -a exit,always -F arch=b64 -S openat -k file_open 2>&1; then
        print_info "  ✓ Added 'openat' audit rule"
        RULES_ADDED=$((RULES_ADDED + 1))
    else
        print_warn "  ✗ Failed to add 'openat' audit rule"
    fi

    if auditctl -a exit,always -F arch=b64 -S execve -k process_exec 2>&1; then
        print_info "  ✓ Added 'execve' audit rule"
        RULES_ADDED=$((RULES_ADDED + 1))
    else
        print_warn "  ✗ Failed to add 'execve' audit rule"
    fi

    # Verify rules were added
    RULE_COUNT=$(auditctl -l 2>/dev/null | wc -l || echo "0")
    # Clean up any newlines or whitespace
    RULE_COUNT=$(echo "$RULE_COUNT" | tr -d '\n\r' | xargs)

    print_info "Audit rules configured (${RULES_ADDED} added, ${RULE_COUNT} total active)"

    if [ "$RULES_ADDED" -eq 0 ]; then
        print_error "No audit rules were successfully added!"
        print_error "Auditd may not be working properly. Check: sudo systemctl status auditd"
        print_error "You may need to enable audit support in your kernel."
        USE_AUDITD=0
    fi

elif [ $USE_STRACE -eq 1 ]; then
    print_info "Starting strace logging..."
    # We'll attach strace to the activity script when it starts
    STRACE_READY=1
else
    print_warn "Skipping syscall logging (no tools available)"
fi

sleep 2
echo ""

# Start activity generation
print_info "Starting activity generation for ${DURATION} seconds..."
echo ""

if [ $USE_STRACE -eq 1 ]; then
    # Run activity script under strace
    strace -f -t -e trace=connect,bind,socket,openat,execve -o "$AUDIT_LOG" "$ACTIVITY_SCRIPT" $DURATION &
    ACTIVITY_PID=$!
    print_info "Activity script running under strace (PID: $ACTIVITY_PID)"
else
    "$ACTIVITY_SCRIPT" $DURATION &
    ACTIVITY_PID=$!
fi

# Monitor progress
ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    REMAINING=$((DURATION - ELAPSED))

    if [ $REMAINING -gt 0 ]; then
        echo -ne "\r${GREEN}[+]${NC} Capturing... ${ELAPSED}s elapsed, ${REMAINING}s remaining    "
    fi
done
echo ""
echo ""

# Wait for activity script to complete
wait $ACTIVITY_PID 2>/dev/null || true
print_info "Activity generation completed"

# Collect final audit logs (if using auditd)
if [ $USE_AUDITD -eq 1 ]; then
    print_info "Collecting audit logs..."

    # Give auditd a moment to flush logs to disk
    sleep 2

    # Try multiple methods to collect logs, in order of preference
    LOG_COLLECTED=0

    # Method 1: Use timestamp-based filtering (most accurate)
    if [ ! -z "$AUDIT_START_TIME" ]; then
        print_info "Attempting timestamp-based collection (start: $AUDIT_START_TIME)..."
        # Pass date and time as separate arguments (unquoted expansion)
        # Note: ausearch doesn't support comma-separated keys, so we collect all events
        ausearch -i --start $AUDIT_START_TIME \
            > "$AUDIT_LOG" 2>/dev/null && LOG_COLLECTED=1
    fi

    # Method 2: If timestamp failed, try recent events (last 5 minutes)
    if [ $LOG_COLLECTED -eq 0 ]; then
        print_warn "Timestamp search failed, trying recent events..."
        ausearch -i --start recent \
            > "$AUDIT_LOG" 2>/dev/null && LOG_COLLECTED=1
    fi

    # Method 3: Last resort - get events from last hour
    if [ $LOG_COLLECTED -eq 0 ]; then
        print_warn "Still no logs, trying last hour..."
        ausearch -i --start now-1h \
            > "$AUDIT_LOG" 2>/dev/null && LOG_COLLECTED=1
    fi

    # Check if we got any data
    if [ -s "$AUDIT_LOG" ]; then
        print_info "Audit logs collected successfully"

        # Optionally convert to JSON format for easier processing
        JSON_AUDIT_LOG="${AUDIT_LOG%.log}.json"
        print_info "Converting to JSON format for Offline Analysis compatibility..."

        # Simple conversion: parse ausearch interpreted output into JSON
        python3 -c "
import sys
import json
import re
from datetime import datetime

events = []
current_event = {}

try:
    with open('$AUDIT_LOG', 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('----'):
                if current_event and 'syscall' in current_event:
                    events.append(current_event)
                current_event = {}
                continue

            # Parse key=value pairs
            if '=' in line:
                parts = line.split()
                for part in parts:
                    if '=' in part:
                        key, val = part.split('=', 1)
                        current_event[key.lower()] = val.strip('\"')

            # Extract timestamp if present
            if line.startswith('time->'):
                try:
                    time_str = line.split('->', 1)[1].strip()
                    current_event['timestamp'] = time_str
                except:
                    pass

        # Don't forget last event
        if current_event and 'syscall' in current_event:
            events.append(current_event)

    # Write JSON
    with open('$JSON_AUDIT_LOG', 'w') as f:
        for event in events:
            json.dump(event, f)
            f.write('\n')

    print(f'Converted {len(events)} events to JSON', file=sys.stderr)

except Exception as e:
    print(f'Warning: JSON conversion failed: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1

        if [ -f "$JSON_AUDIT_LOG" ] && [ -s "$JSON_AUDIT_LOG" ]; then
            print_info "JSON conversion complete: $JSON_AUDIT_LOG"
        else
            print_warn "JSON conversion failed, using raw format"
        fi

    else
        print_error "Failed to collect audit logs - file is empty"
        print_error "This may be because:"
        echo "  1. No events matched the audit rules during capture"
        echo "  2. Auditd is not logging properly"
        echo "  3. Insufficient permissions to read audit logs"
        echo ""
        echo "Debug tips:"
        echo "  - Check audit daemon: sudo systemctl status auditd"
        echo "  - Check audit log: sudo tail /var/log/audit/audit.log"
        echo "  - List active rules: sudo auditctl -l"
    fi

    # Clean up audit rules
    auditctl -D > /dev/null 2>&1 || true
fi

# Note: If using strace, logs are already written to $AUDIT_LOG

sleep 2
print_info "Capture completed successfully!"