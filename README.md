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

- **DDoS Detection**: Sliding window per-flow packet counter
- **Rule Matching**: Proto/port based rule matching in kernel
- **XDP Drop**: Blocking malicious traffic (action=drop)
- **Rule File Parser**: Snort-like rule format support
- **Event Logging**: JSON output to file or stdout

### Rule Format

```
<id> <proto> <dst_port> "<content>" "<message>"
```

| Field | Values |
|-------|--------|
| `id` | Positive integer rule ID |
| `proto` | `tcp`/`6`, `udp`/`17`, `any`/`0` |
| `dst_port` | Port number or `any`/`0` |
| `content` | Substring to match (empty = match all) |
| `message` | Alert description |

**Actions**:
- `action=0`: log only
- `action=1`: drop (requires `drop_enabled=1` at compile time)
- `action=2`: alert

### Event Types

| Type | Description |
|------|-------------|
| `0` | RULE_MATCH — Kernel rule matched |
| `1` | DDOS — DDoS threshold exceeded |
| `4` | DPI_REQUEST — Needs user-space content inspection |

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

## Future Enhancements

### AF_XDP Support (Planned)
- Zero-copy packet access from user space
- Full BMH content matching on packet payload
- Requires: kernel headers with `CONFIG_XDP_SOCKETS=y`

### Runtime Drop Configuration (Planned)
- BPF skeleton API for runtime `drop_enabled` control

---

## License

MIT
