# IDPS — Intrusion Detection & Prevention System

A high-performance Network Intrusion Detection System (NIDS) written in C++17, designed for Linux with a lock-free, zero-copy pipeline architecture.

## Architecture

```
NIC (AF_PACKET)
     │
     ▼
CaptureThread ──► SPSCQueue ──► ProcessingThread
     │                                │
  PacketPool ◄────────────────────────┘
                                      │
                          ┌─────── Pipeline ───────┐
                          │  Preprocess             │
                          │  Decode (IPv4/TCP/UDP)  │
                          │  Detection (DDoS)       │
                          │  Matching (BMH rules)   │
                          │  Event                  │
                          └─────────────────────────┘
                                      │
                               EventQueue
                                      │
                               CommThread ──► log file / stdout
```

### Key Design Points

| Component | Implementation |
|-----------|---------------|
| Packet pool | Lock-free Treiber stack (ABA-tagged 64-bit CAS) |
| Inter-thread queue | Bounded SPSC ring buffer (power-of-2, acquire/release) |
| Pattern matching | Boyer-Moore-Horspool (no external dependency) |
| DDoS detection | Fixed sliding-window per-flow packet counter |
| Flow identification | FNV-1a hash over IPv4 5-tuple |
| NIC capture | Linux `AF_PACKET` + `SOCK_RAW` (`ETH_P_ALL`) |
| CPU pinning | `pthread_setaffinity_np` per thread |

---

## Directory Structure

```
idps/
├── CMakeLists.txt
├── rules.txt                   # Detection rules (example)
├── docs/
│   ├── arch.md                 # Architecture design document
│   └── NIDS_SEPC.md            # Requirements specification
└── src/
    ├── main.cpp
    ├── core/
    │   ├── packet.h            # PacketSlot, PipelineContext
    │   ├── pool.hpp            # Lock-free PacketPool
    │   ├── spsc_queue.hpp      # SPSC ring queue
    │   ├── stage.h             # IStage interface + StageStats
    │   ├── pipeline.h          # Pipeline chain executor
    │   ├── logger.h / .cpp     # Leveled logger (TRACE–ERR)
    ├── ipc/
    │   ├── sec_event.h         # SecEvent struct + JSON serialization
    │   ├── event_queue.hpp/.cpp
    ├── nic/
    │   ├── nic_interface.h     # INic abstract interface
    │   ├── af_packet_nic.h/.cpp
    │   └── mock_nic.h          # MockNic for unit testing
    ├── stages/
    │   ├── net_headers.h       # Packed Ethernet/IPv4/TCP/UDP headers
    │   ├── preprocess_stage    # Size sanity check
    │   ├── decode_stage        # Ethernet→IPv4→TCP/UDP decode
    │   ├── detection_stage     # Per-flow DDoS detection
    │   ├── matching_stage      # BMH content matching
    │   └── event_stage         # Alert → SecEvent push
    ├── threads/
    │   ├── capture_thread      # NIC → pool → queue
    │   ├── processing_thread   # queue → pipeline → pool free
    │   └── comm_thread         # EventQueue → file/stdout
    └── app/
        ├── nids_app.h/.cpp     # Wires all subsystems
└── tests/
    ├── test_pool.cpp           # 5 tests
    ├── test_queue.cpp          # 6 tests
    ├── test_stages.cpp         # 13 tests
    ├── test_pipeline.cpp       # 5 tests
    └── test_integration.cpp    # 3 end-to-end tests
```

---

## Build

### Prerequisites

- GCC 9+ or Clang 10+ (C++17)
- CMake 3.16+
- Linux (AF_PACKET requires Linux kernel)

Dependencies are fetched automatically via CMake `FetchContent`:
- [GoogleTest v1.14.0](https://github.com/google/googletest)
- [nlohmann/json v3.11.3](https://github.com/nlohmann/json)

### Compile

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### Run Tests

```bash
cd build && ctest --output-on-failure
# 32/32 tests passed
```

---

## Usage

```bash
sudo ./build/bin/nids <iface> [ddos_threshold] [rules_file] [event_log] [log_level]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `iface` | *(required)* | Network interface, e.g. `eth0` |
| `ddos_threshold` | `10000` | Packets per window before DDoS alert |
| `rules_file` | *(none)* | Path to rules file |
| `event_log` | `-` (stdout) | Path to JSON event log, `-` for stdout |
| `log_level` | `info` | `trace` / `debug` / `info` / `warn` / `error` / `off` |

### Examples

```bash
# Monitor eth0, log alerts to stdout
sudo ./build/bin/nids eth0

# Full configuration with debug logging
sudo ./build/bin/nids eth0 5000 rules.txt /tmp/nids_events.json debug

# Silent mode (events only, no diagnostic logs)
sudo ./build/bin/nids eth0 10000 rules.txt /var/log/nids.json off
```

---

## Rules File

One rule per line. Lines starting with `#` are comments.

```
<id> <proto> <dst_port> "<content>" "<message>"
```

| Field | Values |
|-------|--------|
| `id` | Positive integer rule ID |
| `proto` | `6`=TCP, `17`=UDP, `0`=any |
| `dst_port` | Destination port, `0`=any |
| `content` | Payload substring to match (empty = match all) |
| `message` | Human-readable alert description |

### Example rules.txt

```
# HTTP attacks
1 6 80 "GET /evil" "Suspicious HTTP GET request"
2 6 80 "/etc/passwd" "Directory traversal attempt"
3 6 80 "UNION SELECT" "SQL injection attempt"

# Any DNS traffic
7 17 53 "" "DNS query detected"

# SSH connections
8 6 22 "" "SSH connection attempt"
```

---

## Log Output

```
[ INFO][14:23:01.042][app       ] pipeline started on iface='eth0' ddos_threshold=10000 rules='rules.txt'
[ INFO][14:23:01.043][capture   ] thread started on iface='eth0' cpu=-1
[ INFO][14:23:01.043][process   ] thread started cpu=-1
[TRACE][14:23:01.150][decode    ] proto=6 src=192.168.1.5:54321 dst=10.0.0.1:80 len=74 hash=0x3F8A12BC
[ INFO][14:23:01.150][matching  ] rule #1 matched: proto=6 dst_port=80 content='GET /evil' | Suspicious HTTP GET request
[ INFO][14:23:01.150][event     ] RULE_MATCH   rule_id=1   src=192.168.1.5:54321  dst=10.0.0.1:80    proto=6
[ WARN][14:23:02.001][detection ] DDoS ALERT flow=0xABCD1234 pkt_count=10001 >= threshold=10000
[ INFO][14:23:11.000][capture   ] stats: captured=100000 dropped_pool=0 dropped_queue=0
```

### Event JSON output

```json
{"type":1,"ts":1709123456789,"src":"192.168.1.5:54321","dst":"10.0.0.1:80","proto":6,"rule_id":1,"msg":"Snort rule match"}
```

---

## License

MIT
