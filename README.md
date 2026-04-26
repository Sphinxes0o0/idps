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
│                          ▼                                  │
│                    ┌──────────┐                            │
│                    │ Ringbuf  │ → Userspace                │
│                    └──────────┘                            │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    Userspace (nids)                          │
│   EbpfNic → RingbufReader → EventQueue → CommThread → JSON  │
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

### eBPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `conn_track` | LRU_HASH | 5-tuple flow state |
| `rules` | HASH | Rule table (proto + port) |
| `stats` | PERCPU_ARRAY | Statistics counters |
| `config` | ARRAY | Runtime configuration |
| `events` | RINGBUF | Alert events (zero-copy) |

---

## Build

### Prerequisites

- GCC 9+ or Clang 10+ (C++17)
- CMake 3.16+
- Linux (XDP requires Linux kernel)
- libbpf, clang (for BPF)

### Compile

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run Tests

```bash
cd build && ctest --output-on-failure
# 20/20 tests passed
```

---

## Usage

```bash
sudo ./build/bin/nids <iface> [event_log] [log_level]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `iface` | *(required)* | Network interface for XDP, e.g. `eth0` |
| `event_log` | `-` (stdout) | Path to JSON event log, `-` for stdout |
| `log_level` | `info` | `trace` / `debug` / `info` / `warn` / `error` / `off` |

### Examples

```bash
# Monitor eth0, log events to stdout
sudo ./build/bin/nids eth0

# Full configuration with debug logging
sudo ./build/bin/nids eth0 /tmp/nids_events.json debug
```

---

## Event JSON Output

```json
{"type":1,"ts":1709123456789,"src":"192.168.1.5:54321","dst":"10.0.0.1:80","proto":6,"rule_id":1,"msg":"Rule matched"}
```

### Event Types

| Type | Description |
|------|-------------|
| `0` | RULE_MATCH — Snort-like rule matched |
| `1` | DDOS — DDoS threshold exceeded |

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
