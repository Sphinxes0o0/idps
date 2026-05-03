# D-01: nids_common.h Structure Memory Layout

This document describes the memory layout and alignment requirements for key structures in `nids_common.h`.

## Structure Overview

### flow_key (16 bytes)

```
struct flow_key {
    __u32 src_ip;      // Offset 0  - Source IPv4 address (network byte order)
    __u32 dst_ip;      // Offset 4  - Destination IPv4 address
    __u16 src_port;    // Offset 8  - Source port (network byte order)
    __u16 dst_port;    // Offset 10 - Destination port
    __u8  protocol;    // Offset 12 - IP protocol number (6=TCP, 17=UDP, 1=ICMP)
    __u8  padding[3];  // Offset 13 - Padding to 16-byte alignment
};
```

**Alignment**: 16-byte aligned for optimal hash map key performance.

**Notes**:
- IPv6 addresses are truncated to 32 bits (first word of IPv6 address) for compatibility
- `padding[3]` ensures the structure is a power of 2 size (16 bytes), which is optimal for BPF hash maps

### flow_stats (48 bytes)

```
struct flow_stats {
    __u64 packet_count;    // Offset 0  - Cumulative packet count
    __u64 byte_count;      // Offset 8  - Cumulative byte count
    __u64 last_seen;       // Offset 16 - Timestamp of last packet (ns)
    __u64 window_start;    // Offset 24 - Start of current detection window
    __u32 window_packets;  // Offset 32 - Packets in current window
    __u8  flags;           // Offset 36 - Flow state flags
    __u8  padding[7];      // Offset 37 - Padding to 8-byte alignment
};
```

**Alignment**: 8-byte aligned for per-CPU atomic operations.

### src_track (40 bytes)

```
struct src_track {
    __u64 packet_count;    // Offset 0  - Packets in window
    __u64 last_seen;       // Offset 8  - Last packet timestamp (ns)
    __u64 window_start;    // Offset 16 - Window start timestamp
    __u8  flags;           // Offset 24 - State flags
    __u8  padding[7];      // Offset 25 - Padding
};
```

**Usage**: Used for SYN flood, ICMP flood, TCP ACK/FIN/RST flood tracking.

### syn_flood_key (12 bytes)

```
struct syn_flood_key {
    __u32 src_ip;    // Offset 0  - Source IP
    __u32 dst_ip;    // Offset 4  - Destination IP
    __u16 dst_port;  // Offset 8  - Destination port
    __u8  padding[2]; // Offset 10 - Padding
};
```

### alert_event (40 bytes)

```
struct alert_event {
    __u64 timestamp;  // Offset 0  - Event timestamp (ns since boot)
    __u32 src_ip;    // Offset 8  - Source IP
    __u32 dst_ip;    // Offset 12 - Destination IP
    __u16 src_port;  // Offset 16 - Source port
    __u16 dst_port;  // Offset 18 - Destination port
    __u8  protocol;  // Offset 20 - Protocol
    __u8  severity;  // Offset 21 - Severity level (0-4)
    __u32 rule_id;   // Offset 22 - Rule ID that triggered event
    __u8  event_type; // Offset 26 - Event type enum
    __u8  padding[3]; // Offset 27 - Padding
};
```

**Alignment**: 8-byte aligned for ringbuf zero-copy operations.

### rule_entry (16 bytes)

```
struct rule_entry {
    __u32 rule_id;       // Offset 0  - Unique rule identifier
    __u8  action;        // Offset 4  - 0=log, 1=drop, 2=alert
    __u8  severity;      // Offset 5  - 0=INFO to 4=CRITICAL
    __u8  protocol;      // Offset 6  - 6=TCP, 17=UDP, 0=any
    __u16 dst_port;      // Offset 7  - Start port (or single port)
    __u16 dst_port_max;  // Offset 9  - End port for range (0=single)
    __u8  dpi_needed;    // Offset 11 - 1=requires user-space DPI
    __u8  padding[2];    // Offset 12 - Padding
};
```

### frag_entry (104 bytes)

```
struct frag_entry {
    __u64 first_seen;       // Offset 0  - First fragment timestamp
    __u64 last_seen;        // Offset 8  - Last fragment timestamp
    __u32 total_length;     // Offset 16 - Reassembled packet length
    __u32 ip_id;            // Offset 20 - IP identification
    __u8  frag_count;       // Offset 24 - Fragments received
    __u8  complete;         // Offset 25 - Reassembly complete flag
    __u8  more_fragments;   // Offset 26 - MF flag from first fragment
    __u8  ip_version;       // Offset 27 - IP version (4 or 6)
    __u32 src_ip;           // Offset 28 - 5-tuple for reassembly
    __u32 dst_ip;           // Offset 32
    __u16 src_port;         // Offset 36
    __u16 dst_port;         // Offset 38
    __u8  protocol;         // Offset 40
    __u8  padding;          // Offset 41
    struct frag_frag_meta frags[8];  // Offset 44 - 8 * 12 = 96 bytes
};
```

### frag_frag_meta (12 bytes)

```
struct frag_frag_meta {
    __u32 buf_id;   // Offset 0  - Buffer ID in frag_buffers map
    __u16 offset;   // Offset 4  - Fragment offset in reassembled packet
    __u16 size;     // Offset 6  - Fragment data size
};
```

## Alignment Requirements Summary

| Structure | Size | Alignment | Reason |
|-----------|------|-----------|--------|
| flow_key | 16 | 16-byte | Power-of-2 for optimal hash map |
| flow_stats | 48 | 8-byte | 8-byte for atomic operations |
| src_track | 40 | 8-byte | 8-byte for atomic operations |
| alert_event | 40 | 8-byte | Ringbuf zero-copy requirement |
| rule_entry | 16 | 4-byte | Packed for memory efficiency |
| frag_entry | 104 | 8-byte | Array element of frag_frag_meta |
| frag_frag_meta | 12 | 4-byte | Array element in frag_entry |

## BPF Map Key Considerations

1. **Power-of-2 sizes**: Keys should be power-of-2 sized for optimal hash map performance
2. **No pointers**: BPF programs cannot dereference user-space pointers
3. **No unaligned access**: Always respect natural alignment in structures
4. **Padding for keys**: Hash map keys with padding bytes still work correctly

## Common Pitfalls

- `flow_key` padding bytes are included in hash calculation - always zero-initialize
- `frag_entry` contains inline array `frags[MAX_FRAGMENTS]` - total size must be under BPF stack limit (512 bytes)
- IPv6 addresses stored as first 32 bits only - collision possible but acceptable for detection
