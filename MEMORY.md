# IDPS Project Memory

## Project Overview
- **Name**: IDPS — Intrusion Detection & Prevention System
- **Location**: /Users/sphinx/github/idps
- **Language**: C++17
- **Architecture**: eBPF/XDP based NIDS

## Architecture
```
XDP eBPF (内核态)
    ├── 5-tuple 解析
    ├── DDoS 检测 (SYN/ICMP flood, DNS amplification)
    ├── 端口扫描检测 (SYN/FIN/NULL/XMAS 跟踪)
    ├── 协议检测 (HTTP/SSH/FTP/Telnet banners)
    ├── 简单规则匹配 (协议+端口)
    └── Ringbuf → 用户态

用户态:
    EbpfNic → RingbufReader → EventQueue → CommThread → JSON 日志
    XdpProcessor (AF_XDP) → TLS 检测 (version/SNI/cipher)
```

## Build & Run
```bash
# Build in ebpf-test container (has bpftool)
docker exec ebpf-test bash -c 'cd /idps && rm -rf build && cmake -S . -B build && cmake --build build'

# Run tests (ctest has path issues - run binaries directly)
docker exec ebpf-test bash -c 'cd /idps/build && ./bin/test_pool && ./bin/test_queue && ./bin/test_rule_parser'
```

## Implemented Features
- [x] SYN/ICMP Flood Detection
- [x] DNS Amplification Detection
- [x] IPv4/IPv6 Defragmentation (LRU-managed)
- [x] Port Scan Detection (SYN/FIN/NULL/XMAS)
- [x] Protocol Detection (HTTP, SSH, FTP, Telnet banners)
- [x] TLS/HTTPS Detection via AF_XDP (weak version, SNI, cipher)

## Key Files
| File | Purpose |
|------|---------|
| `bpf/nids_bpf.c` | XDP eBPF 程序 |
| `bpf/nids_common.h` | Maps, structs, constants (kernel + userspace) |
| `src/nic/ebpf_nic.h/cpp` | eBPF NIC 接口 |
| `src/ebpf/ebpf_loader.h/cpp` | libbpf 加载器 |
| `src/ebpf/ringbuf_reader.h/cpp` | Ringbuf 事件读取 |
| `src/xdp/af_xdp.cpp` | AF_XDP 用户态 DPI + TLS 检测 |
| `src/app/nids_app.h/cpp` | 应用主类 |
| `src/threads/comm_thread.h/cpp` | 事件日志线程 |

## Dependencies
- libbpf, clang (for BPF), libelf-dev, nlohmann/json, GoogleTest
