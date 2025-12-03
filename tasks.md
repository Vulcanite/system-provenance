# Tasks

Project focus: Post Mortem Forensic Analysis

- eBPF + PCAP Collector in Golang
  1. Capture Syscall Events using eBPF especially network ones for forensics and store in ebpf index
  2. Capture Networks events like PCAP and store in pcap index
  3. Capturing events should be configurable via config.json, like if I want to run both eBPF and PCAP or only eBPF or only PCAP
  4. Event Storage should be configurable like Elasticsearch or Any in the config.json, for now we will only support File and ES
  5. File Logging will be always enabled but can be disabled via config.json
  6. Modular Programming



# PCAP Features

1. Integrate gopacket library
2. Open network interface with pcap.OpenLive()
3. Implement BPF filter ("tcp or udp")
4. Extract 5-tuple from packets (src_ip, dst_ip, src_port, dst_port, protocol)
5. Implement flow aggregation (map of FlowKey → FlowStats)
6. Track packet count, byte count per flow
7. Extract TCP flags (SYN, ACK, FIN, RST)
8. Implement DNS packet parsing
9. Build DNS cache (IP → domain mapping)
10. Add DNS cache TTL (5 minutes)
11. Enrich flows with domain names