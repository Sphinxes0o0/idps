# IDPS Architecture

## Overview

IDPS (Intrusion Detection & Prevention System) uses XDP/eBPF for kernel-level packet processing with a minimal userspace component. The system is designed for high-performance network intrusion detection at the kernel level.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      XDP/eBPF (Kernel)                      │
│   ┌──────────┐  ┌────────────┐  ┌────────────┐           │
│   │  Parser  │→ │  Flow Trk  │→ │ DDoS Detect│           │
│   │ (5-tuple)│  │  (LRU)    │  │  (window)  │           │
│   └──────────┘  └────────────┘  └────────────┘           │
│                          │                                  │
│   ┌──────────┐          │                                  │
│   │  Rules   │──────────┘                                  │
│   │ (proto/  │                                           │
│   │  port)   │                                           │
│   └──────────┘          │                                  │
│                          ▼                                  │
│                    ┌──────────┐                            │
│                    │ Ringbuf  │ → Userspace               │
│                    └──────────┘                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Userspace (nids)                          │
│   EbpfNic → RingbufReader → EventQueue → CommThread → JSON  │
│                                                                  │
│   DPI Infrastructure:                                           │
│   - BMH Boyer-Moore-Horspool algorithm (utils/bmh_search.h)  │
│   - Rule parser (rules/rule_parser.h)                        │
│   - EVENT_DPI_REQUEST handling (placeholder)                │
└─────────────────────────────────────────────────────────────┘
```

## Components

| Component | Location | Description |
|-----------|----------|-------------|
| XDP/eBPF | `bpf/nids_bpf.c` | Kernel packet processing, DDoS detection, flow tracking |
| EbpfLoader | `src/ebpf/ebpf_loader.cpp` | libbpf wrapper, XDP attach/detach |
| RingbufReader | `src/ebpf/ringbuf_reader.cpp` | Poll events from BPF Ringbuf |
| EbpfNic | `src/nic/ebpf_nic.cpp` | INic interface implementation |
| CommThread | `src/threads/comm_thread.cpp` | Event logging to JSON |
| RuleParser | `src/rules/rule_parser.cpp` | Snort-like rule file parser |
| BMHSearch | `src/utils/bmh_search.h` | Boyer-Moore-Horspool content matching |

## eBPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `conn_track` | LRU_HASH | 5-tuple flow state |
| `rules` | HASH | Rule table (proto + port + dpi_needed flag) |
| `stats` | PERCPU_ARRAY | Statistics counters |
| `config` | ARRAY | Runtime configuration |
| `events` | RINGBUF | Alert events (zero-copy) |

## Data Flow

1. **Packet Arrival**: XDP receives packet at kernel entry
2. **Parsing**: 5-tuple extracted (src/dst IP, src/dst port, protocol)
3. **Flow Tracking**: LRU hash map tracks flow state
4. **DDoS Detection**: Sliding window counter per flow
5. **Rule Matching**: Kernel checks proto/port rules (O(1) hash lookup)
6. **Event Delivery**: Events sent via BPF Ringbuf (zero-copy)
7. **User-space Processing**: BMH content matching via AF_XDP when needed

## Event Types

| Type | Name | Description |
|------|------|-------------|
| `0` | RULE_MATCH | Kernel rule matched |
| `1` | DDOS | DDoS threshold exceeded |
| `2` | FLOOD | SYN/ICMP flood detected |
| `3` | DNS_AMP | DNS amplification attack detected |
| `4` | DPI_REQUEST | Needs user-space content inspection |
| `5` | BMH_MATCH | User-space BMH pattern match |
