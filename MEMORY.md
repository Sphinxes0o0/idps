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
# Build in Docker container (has all kernel headers)
docker run --rm -v $(pwd):/idps -w /idps ubuntu:22.04 bash -c \
  'apt-get update > /dev/null 2>&1 && apt-get install -y cmake clang llvm libbpf-dev pkg-config make git libelf-dev nlohmann-json3-dev > /dev/null 2>&1 && cmake -S . -B build && cmake --build build'

# Run tests (execute binaries directly - ctest has path issues)
docker run --rm -v $(pwd):/idps -w /idps ubuntu:22.04 bash -c \
  'cd /idps/build && ./bin/test_pool && ./bin/test_queue && ./bin/test_rule_parser'
```

## External Dependencies
- **libbpf-bootstrap**: https://github.com/libbpf/libbpf-bootstrap - BPF 应用开发脚手架
  - 提供 tracepoint 宏 (`BPF_TRACE_sys_enter` 等)
  - 参考示例: `examples/c/bootstrap.bpf.c` (process 跟踪)
  - 参考示例: `examples/c/fentry.bpf.c` (fentry/fexit 跟踪)

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
