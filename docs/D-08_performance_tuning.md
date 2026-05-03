# D-08: Performance Tuning Guide

This guide explains how to tune IDPS performance parameters for your hardware.

## AF_XDP UMEM Configuration

### Key Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `num_frames` | 4096 | Number of UMEM frames (must be power of 2) |
| `frame_size` | 4096 | Size of each frame in bytes |

### UMEM Sizing Formula

```
UMEM Size = num_frames * frame_size
```

**Minimum recommended:** 4096 * 4096 = 16 MB
**High-performance:** 16384 * 4096 = 64 MB

### Tuning for Throughput

| Hardware | Recommended `num_frames` | Notes |
|----------|--------------------------|-------|
| Low-end NIC | 2048 | Reduces memory pressure |
| Standard NIC | 4096 | Good balance |
| High-speed NIC | 8192-16384 | 10GbE+ recommended |
| Multi-queue NIC | 4096 per queue | Each queue needs its own UMEM |

### Tuning for Latency

For lower latency detection:
- Use smaller `frame_size` (2048) if most packets are small
- Reduce `num_frames` to decrease completion ring processing
- Use larger `frame_size` (4096 or 8192) for jumbo frames

## Batch Size Configuration

### process_packets() Batch Size

```cpp
static constexpr int BATCH_SIZE = 64;
```

**Location:** `src/xdp/af_xdp.cpp` line 300

| Batch Size | Use Case |
|------------|----------|
| 32 | Low traffic, latency-sensitive |
| 64 | Default, balanced |
| 128 | High throughput, batch processing |
| 256 | Very high traffic (10GbE+) |

## eBPF Map Sizing

### Connection Tracking

```c
#define MAX_FLOWS 100000
```

| Memory | Max Flows | Notes |
|--------|-----------|-------|
| ~8 MB | 100,000 | Default |
| ~16 MB | 200,000 | High-connection environments |
| ~40 MB | 500,000 | Data center workloads |

### Flow Entry Size

```c
struct flow_stats {
    __u64 packet_count;     // 8 bytes
    __u64 byte_count;       // 8 bytes
    __u64 last_seen;        // 8 bytes
    __u64 window_start;     // 8 bytes
    __u32 window_packets;   // 4 bytes
    __u8  flags;            // 1 byte
    __u8  padding[7];       // 7 bytes
    // Total: 44 bytes per entry
};
```

### Rule Maps

```c
#define MAX_RULES 50000
```

| Memory | Max Rules | Notes |
|--------|-----------|-------|
| ~6 MB | 50,000 | Default |
| ~12 MB | 100,000 | Large rule sets |
| ~60 MB | 500,000 | Enterprise deployments |

### DDoS Detection

```c
#define DDoS_THRESHOLD_DEFAULT 10000
#define PORT_SCAN_THRESHOLD_DEFAULT 20
```

| Threshold | Packets/Second | Detection Sensitivity |
|-----------|----------------|-----------------------|
| 1000 | Low | High false positive |
| 10000 | Medium | Balanced |
| 50000 | High | Low false positive |

## Kernel Buffer Sizes

### Ringbuf Size

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  /* 256KB ring buffer */
} events SEC(".maps");
```

| Size | Events/Second | Latency |
|------|---------------|---------|
| 64 KB | ~50,000 | Lower latency |
| 128 KB | ~100,000 | Balanced |
| 256 KB | ~200,000 | Higher throughput |

### Fragment Maps

```c
#define MAX_FRAGMENTS 8
#define FRAG_TIMEOUT_NS 30000000000ULL  // 30 seconds
```

| Parameter | Effect |
|-----------|--------|
| `MAX_FRAGMENTS` | Higher allows larger fragmented packets but uses more memory |
| `FRAG_TIMEOUT_NS` | Longer timeout increases memory usage |

## poll() Timeout

```cpp
int ret = poll(&pfd, 1, 100);  // 100ms timeout
```

| Timeout | Use Case |
|---------|----------|
| 10ms | Ultra-low latency |
| 100ms | Default, balanced |
| 500ms | Power saving, low traffic |

## Hardware-Specific Recommendations

### Multi-Queue NIC Configuration

For NICs with multiple queues:
- Bind each queue to a separate AF_XDP socket
- Each queue needs its own UMEM
- Use RSS (Receive Side Scaling) to distribute traffic

```bash
# Check NIC queues
ethtool -l eth0

# Set queue count
ethtool -L eth0 combined 4
```

### NUMA Awareness

For multi-socket systems:
- Pin AF_XDP threads to specific CPU cores
- Use local NUMA node for UMEM allocation
- Reduces cross-NUMA memory access

```bash
# Check NUMA topology
numactl --hardware

# Pin thread to node 0
numactl --cpunodebind=0 --membind=0 ./nids eth0
```

### Memory HugePages

Enable hugepages for better UMEM performance:

```bash
# Check current hugepage size
grep Hugepagesize /proc/meminfo

# Set hugepages
echo 64 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
```

## Monitoring Performance

### Key Metrics

| Metric | Counter | Description |
|--------|---------|-------------|
| Packets processed | `rx_count_` | Total packets via AF_XDP |
| Packets dropped | `drop_count_` | Dropped in AF_XDP |
| DPI matches | `dpi_match_count_` | BMH pattern matches |
| Ringbuf utilization | `events` ring | Monitor via bpftool |

### bpftool Commands

```bash
# View map statistics
bpftool map show

# View map contents
bpftool map dump id <id>

# Monitor ringbuf
bpftool prog dump xlated <prog_id> | grep ringbuf
```

### Performance Counters

```bash
# XDP statistics
cat /proc/net/xdp_statistics

# NIC statistics
ethtool -S eth0
```

## Tuning Checklist

1. [ ] Start with default values
2. [ ] Measure baseline throughput (`/proc/net/dev`)
3. [ ] Adjust `num_frames` based on packet drop rate
4. [ ] Tune batch size for throughput/latency balance
5. [ ] Configure DDoS thresholds based on legitimate traffic
6. [ ] Enable hugepages for production
7. [ ] Pin threads to CPU cores
8. [ ] Monitor and iterate

## Common Issues

### Packet Drops

| Cause | Solution |
|-------|----------|
| Fill ring empty | Increase `num_frames` |
| Completion ring full | Process in larger batches |
| UMEM exhausted | Increase UMEM size |

### High CPU Usage

| Cause | Solution |
|-------|----------|
| Small batch size | Increase `BATCH_SIZE` |
| Small UMEM | Increase `num_frames` |
| Too many DPI rules | Move rules to eBPF |
