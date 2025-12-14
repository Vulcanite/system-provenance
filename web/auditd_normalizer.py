#!/usr/bin/env python3
"""
Auditd Log Parser & ECS Normalizer
Converts raw auditd logs to Elastic Common Schema (ECS) format.
Matches the parsing logic from auditd.go for consistency.
"""

import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict


class AuditdNormalizer:
    """
    Parses raw auditd logs and normalizes them to ECS format
    compatible with the ProvenanceGraph analyzer.

    Matches the normalization logic from auditd.go:
    - Groups multi-line events by timestamp:sequence
    - Extracts pid, ppid, comm, exe, auid
    - Maps syscall numbers to names
    - Generates process entity IDs for correlation
    """

    # Syscall name to number mapping (x86_64 architecture)
    # Based on: /usr/include/asm/unistd_64.h
    SYSCALL_MAP = {
        '0': 'read',
        '1': 'write',
        '2': 'open',
        '3': 'close',
        '42': 'connect',
        '43': 'accept',
        '49': 'bind',
        '56': 'clone',
        '57': 'fork',
        '58': 'vfork',
        '59': 'execve',
        '82': 'rename',
        '84': 'renameat',
        '87': 'unlink',
        '257': 'openat',
        '263': 'unlinkat',
        '264': 'renameat',
        '265': 'renameat2',
        '288': 'accept4',
        '322': 'execveat',
    }

    def __init__(self, hostname: str = "audit-host"):
        self.hostname = hostname
        self.event_buffer = defaultdict(list)  # event_id -> list of message dicts

    def parse_auditd_file(self, file_content: str, max_lines: Optional[int] = None,
                         event_type_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Parse auditd log file content and return normalized ECS events.

        Implements same logic as auditd.go:
        1. Parse individual audit messages
        2. Group by event ID (timestamp:sequence)
        3. Coalesce grouped messages into single event
        4. Normalize to ECS format

        Args:
            file_content: Raw auditd log file content
            max_lines: Maximum number of lines to process
            event_type_filter: List of event types to include (e.g., ['EXECVE', 'SYSCALL'])

        Returns:
            List of ECS-normalized events
        """
        lines = file_content.split('\n')
        if max_lines:
            lines = lines[:max_lines]

        # First pass: parse and group lines by event ID
        for line in lines:
            if not line.strip() or line.startswith('#'):
                continue

            parsed = self._parse_auditd_line(line)
            if not parsed:
                continue

            event_type = parsed.get('type')
            event_id = parsed.get('event_id')

            # Apply type filter
            if event_type_filter and event_type not in event_type_filter:
                continue

            if event_id:
                # Store message in buffer grouped by event ID
                self.event_buffer[event_id].append(parsed)

        # Second pass: coalesce grouped messages and normalize to ECS
        ecs_events = []
        for event_id, messages in self.event_buffer.items():
            coalesced = self._coalesce_messages(messages)
            if coalesced:
                normalized = self._normalize_to_ecs(coalesced)
                if normalized:
                    ecs_events.append(normalized)

        # Sort by timestamp (matches Go code behavior)
        ecs_events.sort(key=lambda x: x.get('timestamp', 0))

        return ecs_events

    def _parse_auditd_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single auditd log line.

        Format: type=TYPE msg=audit(timestamp.ms:sequence): key=value ...

        Matches auditd.go's parsing of raw Netlink messages.
        """
        try:
            # Extract type
            type_match = re.search(r'type=(\S+)', line)
            if not type_match:
                return None
            event_type = type_match.group(1)

            # Extract timestamp and sequence from msg=audit(...)
            msg_match = re.search(r'msg=audit\(([0-9.]+):([0-9]+)\)', line)
            if not msg_match:
                return None

            timestamp_str = msg_match.group(1)
            sequence = msg_match.group(2)

            # Convert timestamp to milliseconds (matches Go's UnixMilli())
            timestamp_float = float(timestamp_str)
            timestamp_ms = int(timestamp_float * 1000)

            event_id = f"{timestamp_str}:{sequence}"

            # Extract key-value pairs from the message body
            # Pattern: key=value or key="value" or key='value'
            kv_pattern = r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))'
            matches = re.findall(kv_pattern, line)

            fields = {
                'type': event_type,
                'event_id': event_id,
                'timestamp': timestamp_ms,
                'timestamp_float': timestamp_float,
                'sequence': sequence,
            }

            for key, quoted_dbl, quoted_sgl, unquoted in matches:
                value = quoted_dbl or quoted_sgl or unquoted

                # Decode hex-encoded strings (common in auditd, especially for file paths)
                # Example: 2F62696E2F6C73 -> /bin/ls
                if value and len(value) % 2 == 0 and len(value) > 2:
                    if all(c in '0123456789ABCDEFabcdef' for c in value):
                        try:
                            decoded = bytes.fromhex(value).decode('utf-8', errors='ignore')
                            # Only use decoded if it looks like text
                            if decoded and all(c.isprintable() or c in '\n\t' for c in decoded):
                                value = decoded
                        except:
                            pass

                fields[key] = value

            return fields

        except Exception:
            return None

    def _coalesce_messages(self, messages: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Coalesce multiple audit messages into a single event.

        Implements similar logic to aucoalesce.CoalesceMessages() from Go code:
        - Combines fields from SYSCALL, EXECVE, PATH, SOCKADDR records
        - Merges all key-value pairs into unified event
        - Handles special cases (EXECVE args, PATH items)
        """
        if not messages:
            return None

        # Start with first message as base
        coalesced = messages[0].copy()
        coalesced['types'] = []
        coalesced['raw_data'] = {}

        # Merge all messages
        for msg in messages:
            msg_type = msg.get('type', '')
            coalesced['types'].append(msg_type)

            # Merge all fields into raw_data
            for key, value in msg.items():
                if key not in ['type', 'event_id', 'timestamp', 'timestamp_float', 'sequence']:
                    coalesced['raw_data'][key] = value

            # Handle EXECVE arguments specially (a0, a1, a2, ...)
            if msg_type == 'EXECVE':
                args = []
                i = 0
                while f'a{i}' in msg:
                    arg = msg[f'a{i}']
                    if arg and arg not in ['(null)', '?']:
                        args.append(arg)
                    i += 1
                if args:
                    coalesced['execve_args'] = args

        return coalesced

    def _normalize_to_ecs(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert coalesced auditd event to ECS format compatible with ProvenanceGraph.

        Matches the ECS field mapping from AuditEvent struct in auditd.go:
        - process.pid, process.parent.pid
        - process.name, process.executable
        - process.entity_id, process.parent.entity_id
        - user.id (auid)
        - syscall (mapped from number)
        - file.path
        - destination.ip, destination.port (for network events)
        """
        raw = event.get('raw_data', {})
        event_types = event.get('types', [])

        # Base ECS event structure (matches AuditEvent in Go)
        ecs_event = {
            'event.module': 'auditd',
            'event.kind': 'event',
            'event.category': self._categorize_event(event_types),
            'event.type': event_types,
            'event.sequence': int(event.get('sequence', 0)),
            'host.name': self.hostname,
            '@timestamp': datetime.fromtimestamp(event.get('timestamp_float', 0)).isoformat() + 'Z',
            'timestamp': event.get('timestamp', 0),
            'timestamp_ms': event.get('timestamp', 0),
            'datetime': datetime.fromtimestamp(event.get('timestamp_float', 0)).isoformat(),
        }

        # Extract and map syscall (matches Go's extraction from raw_data)
        syscall_num = raw.get('syscall')
        if syscall_num:
            syscall_name = self.SYSCALL_MAP.get(syscall_num, f'syscall_{syscall_num}')
            ecs_event['syscall'] = syscall_name
            ecs_event['event.action'] = syscall_name
        else:
            # Fallback to event type
            ecs_event['syscall'] = event_types[0].lower() if event_types else 'unknown'
            ecs_event['event.action'] = ecs_event['syscall']

        # Process information (matches Go's ProcessPID, ProcessPPID, ProcessName, ProcessExe)
        pid = raw.get('pid')
        ppid = raw.get('ppid')
        comm = raw.get('comm')
        exe = raw.get('exe')

        if pid:
            try:
                ecs_event['process.pid'] = int(pid)
                # Generate entity ID: hostname:pid:timestamp (simplified version of Go's UUID)
                ecs_event['process.entity_id'] = f"{self.hostname}:{pid}:{event.get('timestamp', 0)}"
            except:
                pass

        if ppid:
            try:
                ecs_event['process.parent.pid'] = int(ppid)
                ecs_event['process.parent.entity_id'] = f"{self.hostname}:{ppid}"
            except:
                pass

        # Process name: strip quotes like Go code does (strings.Trim(v, "\""))
        if comm:
            comm = comm.strip('"').strip("'")
            ecs_event['process.name'] = comm

        # Process executable
        if exe:
            exe = exe.strip('"').strip("'")
            ecs_event['process.executable'] = exe
            # If no comm, extract from exe path (matches Go code logic)
            if not comm and '/' in exe:
                ecs_event['process.name'] = exe.split('/')[-1]

        # User information (matches Go's UserAUID)
        auid = raw.get('auid') or raw.get('uid')
        if auid and auid not in ['-1', '4294967295']:  # Filter unset audit UID
            ecs_event['user.id'] = auid

        # File information
        # Check various auditd file fields: name, path, exe
        filename = raw.get('name') or raw.get('path') or raw.get('file')

        # For EXECVE events, use first argument or exe
        if 'EXECVE' in event_types:
            execve_args = event.get('execve_args', [])
            if execve_args:
                filename = execve_args[0]
                ecs_event['process.args'] = execve_args
                ecs_event['process.command_line'] = ' '.join(execve_args)
            elif exe:
                filename = exe

        if filename and filename not in ['(null)', '?', '']:
            filename = filename.strip('"').strip("'")
            ecs_event['file.path'] = filename
            ecs_event['file.name'] = filename.split('/')[-1] if '/' in filename else filename

        # File descriptor and return value
        fd = raw.get('fd') or raw.get('a0')
        if fd and fd.lstrip('-').isdigit():
            ecs_event['fd'] = int(fd)

        ret = raw.get('exit') or raw.get('res')
        if ret:
            try:
                ecs_event['ret'] = int(ret)
            except:
                ecs_event['ret'] = ret

        # Network information (SOCKADDR records contain network info)
        # Format: saddr=02000050C0A80101... (family=02 00, port, IP)
        if 'SOCKADDR' in event_types or raw.get('saddr'):
            saddr = raw.get('saddr', '')

            if len(saddr) >= 8:
                try:
                    # First 4 chars = family (0200 = AF_INET for IPv4)
                    family = saddr[0:4]
                    if family.upper() == '0200':  # AF_INET (IPv4)
                        # Next 4 chars = port in network byte order (big-endian)
                        port_hex = saddr[4:8]
                        port = int(port_hex, 16)

                        # Next 8 chars = IP address (4 bytes, each 2 hex chars)
                        if len(saddr) >= 16:
                            ip_hex = saddr[8:16]
                            # Convert hex pairs to decimal IP octets
                            ip_parts = [str(int(ip_hex[i:i+2], 16)) for i in range(0, 8, 2)]
                            ip_addr = '.'.join(ip_parts)

                            ecs_event['destination.ip'] = ip_addr
                            ecs_event['destination.port'] = port
                except:
                    pass

        # Success/failure
        success = raw.get('success')
        if success:
            ecs_event['event.outcome'] = 'success' if success == 'yes' else 'failure'

        # Tags (matches Go code)
        ecs_event['tags'] = ['auditd', 'kernel']

        # Store raw data for debugging
        ecs_event['raw_data'] = raw

        # Clean up None values
        ecs_event = {k: v for k, v in ecs_event.items() if v is not None}

        return ecs_event

    def _categorize_event(self, event_types: List[str]) -> List[str]:
        """
        Categorize event types into ECS categories.
        Matches the Category field from auditd.go.
        """
        categories = []

        # Process-related events
        if any(t in ['SYSCALL', 'EXECVE', 'FORK', 'VFORK', 'CLONE'] for t in event_types):
            categories.append('process')

        # File-related events
        if any(t in ['PATH', 'OPEN', 'OPENAT', 'RENAME', 'UNLINK'] for t in event_types):
            categories.append('file')

        # Network-related events
        if any(t in ['SOCKADDR', 'CONNECT', 'BIND', 'ACCEPT'] for t in event_types):
            categories.append('network')

        return categories if categories else ['process']


def parse_auditd_logs(file_content: str, hostname: str = "audit-host",
                      max_lines: Optional[int] = None,
                      event_type_filter: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """
    Convenience function to parse auditd logs and return ECS-normalized events.

    Args:
        file_content: Raw auditd log file content
        hostname: Hostname to use for events (matches host.name in ECS)
        max_lines: Maximum lines to process
        event_type_filter: Event types to include (e.g., ['SYSCALL', 'EXECVE'])

    Returns:
        List of ECS-normalized events ready for ProvenanceGraph analysis
    """
    normalizer = AuditdNormalizer(hostname=hostname)
    return normalizer.parse_auditd_file(file_content, max_lines, event_type_filter)


if __name__ == "__main__":
    # Test with sample auditd log
    sample_log = """type=SYSCALL msg=audit(1234567890.123:100): arch=c000003e syscall=59 success=yes exit=0 a0=7fff1234 a1=7fff5678 a2=7fff9abc items=2 ppid=1000 pid=1001 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=1 comm="bash" exe="/bin/bash" key=(null)
type=EXECVE msg=audit(1234567890.123:100): argc=3 a0="bash" a1="-c" a2="ls /tmp"
type=PATH msg=audit(1234567890.123:100): item=0 name="/bin/bash" inode=12345 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=SYSCALL msg=audit(1234567890.456:101): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7fff1234 a2=0 a3=0 items=1 ppid=1000 pid=1001 auid=1000 uid=1000 gid=1000 comm="ls" exe="/bin/ls" key=(null)
type=PATH msg=audit(1234567890.456:101): item=0 name="/etc/passwd" inode=54321 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL"""

    events = parse_auditd_logs(sample_log, hostname="test-host")

    print(f"Parsed {len(events)} events:\n")
    for i, event in enumerate(events, 1):
        print(f"Event {i}:")
        print(f"  Syscall: {event.get('syscall')}")
        print(f"  PID: {event.get('process.pid')}")
        print(f"  Process: {event.get('process.name')}")
        print(f"  File: {event.get('file.path')}")
        print(f"  Command: {event.get('process.command_line')}")
        print(f"  Timestamp: {event.get('timestamp')}")
        print()
