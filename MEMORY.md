# IDPS Project Memory

## Project Overview
- **Name**: IDPS — Intrusion Detection & Prevention System
- **Location**: /Users/sphinx/github/idps
- **Language**: C++17
- **Architecture**: eBPF/XDP based NIDS

## Architecture (After Cleanup)
```
XDP eBPF (内核态)
    ├── 5-tuple 解析
    ├── DDoS 检测 (滑动窗口)
    ├── 简单规则匹配 (协议+端口)
    └── Ringbuf → 用户态

用户态:
    EbpfNic → RingbufReader → EventQueue → CommThread → JSON 日志
```

## Build & Run (Docker on macOS)
```bash
# Full build
docker run --rm -v $(pwd):/idps -w /idps ubuntu:22.04 bash -c \
  'apt-get update > /dev/null 2>&1 && apt-get install -y cmake clang llvm libbpf-dev pkg-config make git libelf-dev > /dev/null 2>&1 && cmake -S . -B build && cmake --build build -j$(nproc)'

# Run tests
docker run --rm -v $(pwd):/idps -w /idps/build ubuntu:22.04 bash -c \
  'apt-get update > /dev/null 2>&1 && apt-get install -y cmake libelf-dev > /dev/null 2>&1 && ctest --output-on-failure'
```

## Verified (2026-04-26)
- ✅ CMake 配置成功
- ✅ eBPF 编译成功
- ✅ 用户态代码编译成功（无警告）
- ✅ 链接成功
- ✅ 20/20 单元测试通过

## Key Files
| File | Purpose |
|------|---------|
| `bpf/nids_bpf.c` | XDP eBPF 程序 |
| `src/nic/ebpf_nic.h/cpp` | eBPF NIC 接口 |
| `src/ebpf/ebpf_loader.h/cpp` | libbpf 加载器 |
| `src/ebpf/ringbuf_reader.h/cpp` | Ringbuf 事件读取 |
| `src/app/nids_app.h/cpp` | 应用主类 |
| `src/threads/comm_thread.h/cpp` | 事件日志线程 |

## Dependencies
- libbpf
- nlohmann/json
- GoogleTest
- clang (for BPF compilation)
- libelf-dev
