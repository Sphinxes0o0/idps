# IDPS - Intrusion Detection & Prevention System

## Project Overview

IDPS is a high-performance Network Intrusion Detection System using XDP/eBPF for kernel-level packet processing with a minimal userspace component.

**Repository**: `/Users/sphinx/github/idps`
**Build System**: CMake with C++17
**Key Dependencies**: libbpf, clang (for BPF), nlohmann-json, GoogleTest

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
│   - BMH Boyer-Moore-Horspool algorithm (src/utils/bmh_search.h) │
│   - Rule parser (src/rules/rule_parser.h)                      │
│   - AF_XDP processor (src/xdp/af_xdp.h)                       │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
/Users/sphinx/github/idps/
├── bpf/                        # eBPF kernel code
│   ├── nids_bpf.c             # Main XDP/eBPF program
│   └── nids_common.h          # Shared structs, maps, constants (kernel + userspace)
├── src/                        # Userspace application
│   ├── main.cpp               # Entry point, signal handling
│   ├── app/                   # NidsApp - main application class
│   ├── core/                  # Logger, packet structures
│   ├── ebpf/                  # EbpfLoader, RingbufReader
│   ├── ipc/                   # EventQueue, SecEvent
│   ├── metrics/               # Prometheus metrics server
│   ├── nic/                   # EbpfNic (INic interface)
│   ├── rules/                 # RuleParser (Snort-like rules)
│   ├── threads/               # CommThread (JSON logging)
│   ├── utils/                # BMHSearch Boyer-Moore-Horspool
│   └── xdp/                  # AF_XDP processor
├── tests/                     # Unit tests (GoogleTest)
├── deploy/                    # Deployment files (systemd, config)
├── docs/                      # Architecture docs
├── CMakeLists.txt            # Build configuration
├── rules.txt                  # Sample rules file
└── MEMORY.md                 # Project memory notes
```

## Key Components

### Kernel (eBPF) Components

| Component | File | Purpose |
|-----------|------|---------|
| XDP Program | `bpf/nids_bpf.c` | Packet processing, DDoS detection, flow tracking |
| Conn Track | `conn_track` LRU_HASH map | 5-tuple flow state (100k max flows) |
| Rules | `rules` HASH map | Proto/port rule table (50k max rules) |
| Rule Index | `rule_index` HASH map | O(1) proto/port lookup |
| Stats | `stats` PERCPU_ARRAY | Statistics counters |
| Config | `config` ARRAY | Runtime configuration |
| Events | `events` RINGBUF | Zero-copy alert events to userspace |
| SYN Flood | `syn_flood_track` LRU_HASH | SYN flood detection per (src_ip, dst_ip, dst_port) |
| ICMP Flood | `icmp_flood_track` LRU_HASH | ICMP flood detection per src_ip |
| DNS Tracking | `dns_amp_track` | DNS amplification detection (single LRU table keyed by victim_ip) |
| Port Scan | `port_scan_track` LRU_HASH | Port scan detection per (src_ip, dst_ip), tracks SYN/FIN/NULL/XMAS packets |
| Frag Track | `frag_track`, `frag_buffers` | IPv4/IPv6 defragmentation |

### Userspace Components

| Component | File | Purpose |
|-----------|------|---------|
| EbpfLoader | `src/ebpf/ebpf_loader.cpp` | libbpf wrapper, XDP attach/detach |
| RingbufReader | `src/ebpf/ringbuf_reader.cpp` | Poll events from BPF Ringbuf via libbpf |
| EbpfNic | `src/nic/ebpf_nic.cpp` | INic implementation wrapping EbpfLoader |
| EventQueue | `src/ipc/event_queue.cpp` | Thread-safe queue for SecEvent |
| SecEvent | `src/ipc/sec_event.h` | Security event structure |
| CommThread | `src/threads/comm_thread.cpp` | Write events to JSON log (+syslog) |
| RuleParser | `src/rules/rule_parser.cpp` | Parse Snort-like rules |
| BMHSearch | `src/utils/bmh_search.h` | Boyer-Moore-Horspool pattern matching |
| XdpProcessor | `src/xdp/af_xdp.cpp` | AF_XDP user-space DPI with TLS metadata extraction (version, SNI, cipher) and BMH content matching |
| NidsApp | `src/app/nids_app.cpp` | Main app orchestrating all components |
| PrometheusServer | `src/metrics/prometheus_server.cpp` | HTTP metrics endpoint (port 8080) |
| MetricsRegistry | `src/metrics/metrics_registry.cpp` | Prometheus metrics collector |

## Build System

### Build Commands

```bash
# Configure and build
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run tests (execute test binaries directly, ctest has path issues)
cd build && ./bin/test_pool && ./bin/test_queue && ./bin/test_rule_parser
```

### Build Outputs

- `build/bin/nids` - Main executable
- `build/bin/nids_bpf.o` - Compiled eBPF object
- `build/bin/test_*` - Unit test executables

### Key Build Notes

- **Requires Linux** (XDP/eBPF does not work on macOS)
- **clang** compiles BPF code targeting `bpf` architecture
- **bpftool** generates skeleton header at build time
- AF_XDP requires `CONFIG_XDP_SOCKETS=y` in kernel

## Usage

```bash
# Monitor interface with rules
sudo ./build/bin/nids eth0 rules.txt

# Full configuration via JSON config
sudo ./build/bin/nids --config /etc/nids/nids.conf

# With JSON event log and debug logging
sudo ./build/bin/nids eth0 rules.txt /tmp/events.json debug
```

### Configuration File Format (JSON)

```json
{
  "interface": "eth0",
  "rules_file": "/etc/nids/rules.txt",
  "event_log": "/var/log/nids/events.json",
  "use_syslog": true,
  "metrics_port": 8080,
  "pipelines": [
    {"iface": "eth0", "rules_file": "/etc/nids/rules.txt", "ddos_threshold": 10000, "port_scan_threshold": 20}
  ]
}
```

### Signal Handling

- `SIGINT/SIGTERM` - Graceful shutdown
- `SIGUSR1` - Hot reload rules

## Rule Format

```
<id> <proto> <dst_port> "<content>" "<message>" [tls_version=<hex>] [sni="<pattern>"] [cipher=<hex>]
```

| Field | Values |
|-------|--------|
| `id` | Positive integer rule ID |
| `proto` | `tcp`/`6`, `udp`/`17`, `any`/`0` |
| `dst_port` | Port number, `port:port` range, or `any`/`0` |
| `content` | Substring to match (empty = match all on proto/port) |
| `message` | Alert description |
| `tls_version` | Match weak TLS version (e.g. `0x0301` for TLS 1.0) |
| `sni` | Match SNI hostname substring (requires quotes) |
| `cipher` | Match TLS cipher suite (e.g. `0x0005` for RC4) |

**Rules are split into:**
- **Simple rules** (content=""): pushed to eBPF kernel for fast proto/port matching
- **Content rules** (content!="" or TLS options): require user-space matching via AF_XDP

## Event Types

| Type | Value | Description |
|------|-------|-------------|
| `RULE_MATCH` | 0 | Kernel rule matched |
| `DDoS_ALERT` | 1 | Flow exceeded packet threshold |
| `FLOW_THRESHOLD` | 2 | Flow threshold exceeded |
| `NEW_FLOW` | 3 | New flow created |
| `DPI_REQUEST` | 4 | Needs user-space content inspection |
| `SYN_FLOOD` | 5 | SYN flood detected |
| `ICMP_FLOOD` | 6 | ICMP flood detected |
| `DNS_AMP` | 7 | DNS amplification attack detected |
| `HTTP_DETECTED` | 8 | HTTP banner/response detected (port 80/8080) |
| `SSH_BANNER` | 9 | SSH protocol banner detected (port 22) |
| `FTP_CMD` | 10 | FTP command detected (port 21) |
| `TELNET_OPT` | 11 | Telnet option negotiation detected (port 23) |
| `PORT_SCAN` | 12 | Port scan detected (SYN/FIN/NULL/XMAS) |

## Testing

Tests use GoogleTest framework:

```bash
# Run all tests
./build/bin/test_pool
./build/bin/test_queue
./build/bin/test_rule_parser
./build/bin/test_ebpf_loader  # Requires root for BPF
```

Test files:
- `tests/test_pool.cpp` - Memory pool tests
- `tests/test_queue.cpp` - Event queue tests
- `tests/test_rule_parser.cpp` - Rule parser tests
- `tests/test_ebpf_loader.cpp` - eBPF loader tests

## Development Notes

### Data Flow

1. **Packet arrives** at XDP hook in kernel
2. **Parse** - Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
3. **Defrag** - Handle IPv4/IPv6 fragmentation
4. **DDoS Detection** - SYN/ICMP flood, DNS amplification
5. **Flow Tracking** - Update LRU conn_track map
6. **Rule Matching** - O(1) hash lookup via rule_index
7. **Event** - Send via Ringbuf (zero-copy) if match/alert
8. **Userspace** - RingbufReader polls events, pushes to EventQueue
9. **CommThread** - Serializes SecEvent to JSON, writes to log/syslog

### Key Files for Modification

- Adding new eBPF map: Add to `bpf/nids_common.h` and regenerate skeleton
- Adding new detection: Add function in `bpf/nids_bpf.c`, call from `handle_xdp()`
- Adding new event type: Add to `enum event_type` in `bpf/nids_common.h`
- Adding new rule field: Modify `struct rule_entry` and `RuleEntry` in `ebpf_loader.h`
- BMH matching: Uses AF_XDP infrastructure, see `src/xdp/af_xdp.cpp`

### Docker Build (macOS)

Since XDP requires Linux, build in Docker:

```bash
docker run --rm -v $(pwd):/idps -w /idps ubuntu:22.04 bash -c \
  'apt-get update > /dev/null 2>&1 && apt-get install -y cmake clang llvm libbpf-dev pkg-config make git libelf-dev > /dev/null 2>&1 && cmake -S . -B build && cmake --build build'
```

### Build Dependencies

- CMake 3.16+
- GCC 9+ or Clang 10+ (C++17)
- libbpf
- clang (for BPF)
- kernel headers with XDP support
- nlohmann-json (header-only, fetched if not system-installed)
- GoogleTest (fetched if not system-installed)
