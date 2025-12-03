#!/bin/bash
# Generate forensic activity while system-monitor captures events
# No file capture - relies on system-monitor service for eBPF+PCAP

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Configuration
DURATION=${1:-60}
ACTIVITY_SCRIPT="./generate_activity.sh"
EVENTS_DIR="/var/monitoring/events"
OUTPUT_DIR="/var/monitoring/outputs"

print_header "Forensic Activity Generator"
echo ""
print_info "Configuration:"
echo "  - Duration: ${DURATION} seconds"
echo "  - Activity Script: $ACTIVITY_SCRIPT"
echo "  - System Monitor Events: $EVENTS_DIR"
echo "  - System Monitor Outputs: $OUTPUT_DIR"
echo ""

# Check if system-monitor is running
if ! systemctl is-active --quiet system-monitor 2>/dev/null; then
    print_error "system-monitor service is not running!"
    echo ""
    echo "Start it with:"
    echo "  sudo systemctl start system-monitor"
    echo ""
    exit 1
fi

print_info "✓ system-monitor service is running"

# Check activity script
if [ ! -f "$ACTIVITY_SCRIPT" ]; then
    print_error "Activity script not found: $ACTIVITY_SCRIPT"
    exit 1
fi

chmod +x "$ACTIVITY_SCRIPT"

echo ""
print_header "Starting Activity Generation"
echo ""

# Get start time for reference
START_TIME=$(date +%s)
START_DT=$(date +"%Y-%m-%d %H:%M:%S")

print_info "Start time: $START_DT"
print_info "system-monitor is capturing eBPF events + PCAP flows"
echo ""

# Run activity script
print_info "Running activity for ${DURATION} seconds..."
echo ""

"$ACTIVITY_SCRIPT" $DURATION &
ACTIVITY_PID=$!

# Monitor progress
ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    REMAINING=$((DURATION - ELAPSED))

    if [ $REMAINING -gt 0 ]; then
        echo -ne "\r${GREEN}[+]${NC} Activity running... ${ELAPSED}s / ${DURATION}s    "
    fi
done
echo ""

# Wait for activity to complete
wait $ACTIVITY_PID 2>/dev/null || true

END_TIME=$(date +%s)
END_DT=$(date +"%Y-%m-%d %H:%M:%S")

echo ""
print_info "Activity generation completed"
echo ""

# Give system-monitor a moment to flush
print_info "Waiting 5 seconds for system-monitor to flush events..."
sleep 5

print_header "Capture Summary"
echo ""

print_info "Time Range:"
echo "  - Start: $START_DT"
echo "  - End:   $END_DT"
echo "  - Duration: $((END_TIME - START_TIME)) seconds"
echo ""

# Check eBPF events
if [ -f "$EVENTS_DIR/ebpf-events.jsonl" ]; then
    EBPF_SIZE=$(du -h "$EVENTS_DIR/ebpf-events.jsonl" | cut -f1)
    # Count events in time range (approximate)
    RECENT_EVENTS=$(tail -1000 "$EVENTS_DIR/ebpf-events.jsonl" | wc -l)

    print_info "eBPF Events: $EVENTS_DIR/ebpf-events.jsonl"
    echo "  - File size: $EBPF_SIZE"
    echo "  - Recent events: ~$RECENT_EVENTS (last 1000 lines)"
else
    print_warn "eBPF events file not found"
fi

echo ""

# Check PCAP flows
if [ -f "$EVENTS_DIR/pcap-flows.jsonl" ]; then
    PCAP_SIZE=$(du -h "$EVENTS_DIR/pcap-flows.jsonl" | cut -f1)
    RECENT_FLOWS=$(tail -500 "$EVENTS_DIR/pcap-flows.jsonl" | wc -l)

    print_info "PCAP Flows: $EVENTS_DIR/pcap-flows.jsonl"
    echo "  - File size: $PCAP_SIZE"
    echo "  - Recent flows: ~$RECENT_FLOWS (last 500 lines)"
else
    print_warn "PCAP flows file not found"
fi

echo ""
print_header "Analysis Options"
echo ""

print_info "Option 1: Web Interface (Real-time)"
echo "  1. Open web interface"
echo "  2. View eBPF Events or PCAP Flows pages"
echo "  3. Filter by time range: $START_DT to $END_DT"
echo ""

print_info "Option 2: Offline Analysis (PCAP only)"
echo "  1. Open web interface -> Offline Analysis"
echo "  2. Upload a PCAP file captured during this time"
echo "  3. Visualize network traffic patterns"
echo ""

print_info "Option 3: Command Line Analysis"
echo "  # View recent eBPF events:"
echo "  tail -100 $EVENTS_DIR/ebpf-events.jsonl | jq ."
echo ""
echo "  # View recent PCAP flows:"
echo "  tail -50 $EVENTS_DIR/pcap-flows.jsonl | jq ."
echo ""
echo "  # Count events by syscall:"
echo "  jq -r '.syscall' $EVENTS_DIR/ebpf-events.jsonl | tail -1000 | sort | uniq -c | sort -rn"
echo ""

print_info "All data is being continuously captured by system-monitor"
print_info "Events are stored in: $EVENTS_DIR"
echo ""
