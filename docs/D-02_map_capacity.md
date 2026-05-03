# D-02: BPF Map Capacity Planning

This document explains the rationale for key capacity constants and provides guidance for capacity planning.

## Capacity Constants

### MAX_FLOWS: 100,000

```
#define MAX_FLOWS 100000
```

**Purpose**: Maximum number of concurrent flow tracking entries in `conn_track` LRU hash map.

**Rationale**:
- LRU hash automatically evicts oldest entries when capacity is reached
- 100K flows = ~4.8MB for flow keys + ~4.8MB for flow stats = ~10MB total
- Typical server handles 10K-50K concurrent connections
- LRU ensures recent active flows are preserved during attack

**Memory Calculation**:
```
flow_key   = 16 bytes
flow_stats = 48 bytes
Per flow   = 64 bytes
100K flows = 6.4 MB
```

### MAX_RULES: 50,000

```
#define MAX_RULES 50000
```

**Purpose**: Maximum rule entries in the `rules` hash map.

**Rationale**:
- Snort-compatible rulesets can have 20K-50K rules
- Each rule_entry is 16 bytes = 800KB for 50K rules
- Rules are typically static (loaded at startup, rarely updated)
- Rule index provides O(1) lookup for common (protocol, port) pairs

**Rule Index Optimization**:
```
rule_index max_entries = 1024
- Covers common (protocol, port) combinations
- 256 ports * 4 protocols = 1024 potential combinations
- Rule index hit rate typically >95% for well-designed rulesets
```

### DDoS_THRESHOLD_DEFAULT: 10,000

```
#define DDoS_THRESHOLD_DEFAULT 10000
```

**Purpose**: Packet count threshold per flow per window for DDoS detection.

**Rationale**:
- Window size = 1 second (WINDOW_SIZE_NS = 1,000,000,000 ns)
- 10K packets/second per flow is aggressive but legitimate for bulk transfers
- L4 DDoS typically shows 50K-100K pps from single source
- Adjust based on expected legitimate traffic patterns

### PORT_SCAN_THRESHOLD_DEFAULT: 20

```
#define PORT_SCAN_THRESHOLD_DEFAULT 20
```

**Purpose**: Number of unique ports scanned before triggering alert.

**Rationale**:
- Legitimate clients typically connect to <10 ports
- Fast port scan (nmap -T5) can scan 100+ ports/second
- 20 is low enough to catch slow scans, not so low as to false positive

## LRU Hash Map Capacities

### SYN Flood Tracking: 65,536

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    ...
} syn_flood_track SEC(".maps");
```

**Purpose**: Track SYN flood per (src_ip, dst_ip, dst_port) triplet.

**Rationale**:
- 65536 = 2^16, power of 2 for optimal hash distribution
- Each unique (source, destination, port) gets own counter
- LRU eviction handles distributed attack sources gracefully

### ICMP Flood Tracking: 65,536

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    ...
} icmp_flood_track SEC(".maps");
```

**Purpose**: Track ICMP flood per source IP.

**Rationale**:
- Single source can only have one ICMP flood tracking entry
- 65K unique source IPs tracked simultaneously
- LRU ensures most recent flood sources are tracked

### DNS Amplification Tracking: 65,536

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    ...
} dns_amp_track SEC(".maps");
```

**Purpose**: Track DNS amplification per victim IP.

**Rationale**:
- Each victim IP has one tracking entry
- 65K simultaneous victim IPs tracked
- Response/query ratio tracked per victim

### Port Scan Tracking: 65,536

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    ...
} port_scan_track SEC(".maps");
```

**Purpose**: Track port scan per (src_ip, dst_ip) pair.

**Rationale**:
- Tracks which ports have been scanned per source-destination pair
- 65K simultaneous (source, destination) pairs
- Multiple scanners to same target tracked independently

## Defragmentation Capacities

### frag_track: 1,024

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    ...
} frag_track SEC(".maps");
```

**Purpose**: Track concurrent reassembly operations.

**Rationale**:
- Memory-intensive: each entry is ~104 bytes + fragment data
- 1024 concurrent reassemblies = ~1MB per map + fragment buffers
- LRU auto-evicts stale reassemblies after 30 seconds (FRAG_TIMEOUT_NS)

### frag_buffers: 16,384

```
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    ...
} frag_buffers SEC(".maps");
```

**Purpose**: Store actual fragment data.

**Rationale**:
- Each buffer = FRAG_BUFFER_SIZE (128 bytes) + metadata
- 16K buffers = ~2MB total
- Supports up to 8 fragments per reassembly (MAX_FRAGMENTS = 8)
- 16K / 8 = 2K concurrent partial reassemblies

## Ringbuf Capacity

### events: 256 KB

```
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
```

**Purpose**: Zero-copy event transmission to user space.

**Rationale**:
- Each alert_event = 40 bytes
- 256KB / 40 bytes = ~6,500 event slots
- Ringbuf handles burst traffic without dropping
- Consumer (user-space) processes events asynchronously

## Capacity Planning Guidelines

### Memory Budget

| Map | Max Entries | Entry Size | Total Memory |
|-----|-------------|------------|-------------|
| conn_track | 100,000 | 64 bytes | 6.4 MB |
| rules | 50,000 | 16 bytes | 800 KB |
| syn_flood_track | 65,536 | 40 bytes | 2.6 MB |
| icmp_flood_track | 65,536 | 40 bytes | 2.6 MB |
| dns_amp_track | 65,536 | 40 bytes | 2.6 MB |
| port_scan_track | 65,536 | 40 bytes | 2.6 MB |
| frag_track | 1,024 | 104 bytes | 106 KB |
| frag_buffers | 16,384 | 128 bytes | 2 MB |
| rule_index | 1,024 | 20 bytes | 20 KB |
| **Total** | | | **~20 MB** |

### Scaling Considerations

1. **High-bandwidth DDoS**: Increase `ddos_threshold` if legitimate traffic exceeds defaults
2. **Port scan sensitivity**: Lower `port_scan_threshold` for sensitive environments
3. **Fragment handling**: Increase `frag_track` if handling many fragmented attacks
4. **Rule count**: Increase `MAX_RULES` if using large Snort ruleset

### Kernel Memory Limits

BPF map memory is allocated in kernel memory. Default limits:
- `proc/sys/kernel/bpf_max_entries` - global BPF map entry limit
- `ulimit -l` - locked memory limit (must be sufficient for all maps)

Verify with:
```bash
cat /proc/sys/kernel/bpf_max_entries
ulimit -l
```
