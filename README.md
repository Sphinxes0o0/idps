# IDPS — Intrusion Detection & Prevention System

A high-performance Network Intrusion Detection System (NIDS) using XDP/eBPF for kernel-level packet processing with a minimal userspace component.

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
│   - EVENT_DPI_REQUEST handling (placeholder)                  │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | Location | Description |
|-----------|----------|-------------|
| XDP/eBPF | `bpf/nids_bpf.c` | Kernel packet processing, DDoS detection, flow tracking |
| EbpfLoader | `src/ebpf/ebpf_loader.cpp` | libbpf wrapper, XDP attach/detach |
| RingbufReader | `src/ebpf/ringbuf_reader.cpp` | Poll events from BPF Ringbuf |
| EbpfNic | `src/nic/ebpf_nic.cpp` | INic interface implementation |
| CommThread | `src/threads/comm_thread.cpp` | Event logging to JSON |
| RuleParser | `src/rules/rule_parser.cpp` | Snort-like rule file parser |
| BMHSearch | `src/utils/bmh_search.h` | Boyer-Moore-Horspool content matching |

### eBPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `conn_track` | LRU_HASH | 5-tuple flow state |
| `rules` | HASH | Rule table (proto + port + dpi_needed flag) |
| `stats` | PERCPU_ARRAY | Statistics counters |
| `config` | ARRAY | Runtime configuration |
| `events` | RINGBUF | Alert events (zero-copy) |

---

## Features

### Implemented

- **eBPF/XDP Packet Processing**: Kernel-level packet processing with XDP/eBPF
- **Kernel Rule Matching**: Proto/port based rule matching with port range support
- **Hash-Indexed Rule Lookup**: O(1) rule lookup via kernel hash map
- **SYN/ICMP Flood Detection**: Sliding window per-flow packet counter
- **DNS Amplification Detection**: Detection of DNS amplification attacks
- **DDoS Detection via LRU Flow Tracking**: Flow state management with LRU eviction
- **User-Space BMH Content Matching**: Boyer-Moore-Horspool algorithm via AF_XDP
- **BPF Ringbuf Zero-Copy Events**: Efficient event delivery from kernel to userspace
- **BPF Skeleton Auto-Generation**: Compile-time BPF program generation
- **Prometheus Metrics Server**: Metrics exposed on port 8080 (configurable)
- **Syslog Logging**: System log integration
- **Systemd Service + JSON Config**: Full systemd integration with JSON configuration
- **Graceful Shutdown**: SIGINT/SIGTERM/SIGUSR1 signal handling
- **libFuzzer Fuzz Test**: Built-in fuzzing support
- **Tail Call XDP Pipeline Infrastructure**: Extensible XDP program chaining

### Rule Format

```
<id> <proto> <dst_port> "<content>" "<message>"
```

| Field | Values |
|-------|--------|
| `id` | Positive integer rule ID |
| `proto` | `tcp`/`6`, `udp`/`17`, `any`/`0` |
| `dst_port` | Port number, `port:port` range, or `any`/`0` |
| `content` | Substring to match (empty = match all) |
| `message` | Alert description |

**Port Range Syntax**:
- `80` - single port 80
- `80:90` - port range (ports 80 through 90 inclusive)
- `any` or `0` - any port

**Actions**:
- `action=0`: log only
- `action=1`: drop (requires `drop_enabled=1` at runtime via config map)
- `action=2`: alert

### Event Types

| Type | Description |
|------|-------------|
| `0` | RULE_MATCH — Kernel rule matched |
| `1` | DDOS — DDoS threshold exceeded |
| `2` | FLOOD — SYN/ICMP flood detected |
| `3` | DNS_AMP — DNS amplification attack detected |
| `4` | DPI_REQUEST — Needs user-space content inspection |
| `5` | BMH_MATCH — User-space BMH pattern match |

---

## Build

### Prerequisites

- GCC 9+ or Clang 10+ (C++17)
- CMake 3.16+
- Linux (XDP requires Linux kernel)
- libbpf, clang (for BPF)
- kernel headers with XDP support (for AF_XDP)

### Compile

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run Tests

```bash
cd build && ctest --output-on-failure
# 27/27 tests passed
```

---

## Usage

```bash
sudo ./build/bin/nids <iface> [rules_file] [event_log] [log_level]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `iface` | *(required)* | Network interface for XDP, e.g. `eth0` |
| `rules_file` | *(none)* | Path to rules file |
| `event_log` | `-` (stdout) | Path to JSON event log, `-` for stdout |
| `log_level` | `info` | `trace` / `debug` / `info` / `warn` / `error` / `off` |

### Examples

```bash
# Monitor eth0, log events to stdout
sudo ./build/bin/nids eth0

# With rules
sudo ./build/bin/nids eth0 rules.txt

# Full configuration
sudo ./build/bin/nids eth0 rules.txt /tmp/nids_events.json debug
```

---

## macOS Build (Docker)

XDP/eBPF requires Linux. On macOS, verify the build using Docker:

```bash
docker run --rm -v $(pwd):/idps -w /idps ubuntu:22.04 bash -c \
  'apt-get update > /dev/null 2>&1 && apt-get install -y cmake clang llvm libbpf-dev pkg-config make git libelf-dev > /dev/null 2>&1 && cmake -S . -B build && cmake --build build'
```

---

## License

MIT
