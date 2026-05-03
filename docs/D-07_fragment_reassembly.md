# D-07: IP Fragment Reassembly Strategy

This document describes how IDPS handles IPv4 and IPv6 packet fragmentation.

## Overview

Fragment reassembly allows IDPS to detect attacks that span multiple IP fragments, such as fragmented malicious payloads or evasion attempts.

## Fragment Tracking Architecture

```
+------------------+     +------------------+     +------------------+
|   frag_track     | --> |  frag_buffers    | --> |  Reassembled    |
|  (LRU_HASH)      |     |  (LRU_HASH)      |     |  Packet         |
|  Key: frag_key  |     |  Key: buf_id     |     |                 |
+------------------+     +------------------+     +------------------+
     1024 max entries         16384 max entries
```

## Data Structures

### frag_key (Fragment Tracking Key)

```c
struct frag_key {
    __u32 src_ip;      // Source IP
    __u32 dst_ip;      // Destination IP
    __u32 ip_id;       // IP identification field
    __u8  protocol;    // Next header protocol (TCP/UDP/ICMP)
    __u8  ip_version;  // 4 or 6
};
```

### frag_entry (Fragment Metadata)

```c
struct frag_entry {
    __u64 first_seen;       // Timestamp of first fragment
    __u64 last_seen;        // Timestamp of last fragment
    __u32 total_length;     // Total reassembled length
    __u32 ip_id;            // IP identification
    __u8  frag_count;       // Fragments received (max 8)
    __u8  complete;         // Reassembly complete flag
    __u8  more_fragments;   // MF flag from first fragment
    __u8  ip_version;       // IP version (4 or 6)
    struct frag_frag_meta frags[MAX_FRAGMENTS];  // Per-fragment metadata
};
```

### frag_data (Fragment Data Buffer)

```c
struct frag_data {
    __u32 session_id;      // Index into frag_track
    __u16 offset;          // Fragment offset in bytes
    __u16 size;            // Fragment size in bytes
    __u8  data[FRAG_BUFFER_SIZE];  // Actual fragment data
};
```

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_FRAGMENTS` | 8 | Maximum fragments per reassembly |
| `FRAG_TIMEOUT_NS` | 30,000,000,000 (30s) | Reassembly timeout |
| `FRAG_MAX_SIZE` | 65,535 | Maximum reassembled packet size |
| `FRAG_BUFFER_SIZE` | 128 | Size of each fragment buffer entry |

## IPv4 Fragment Handling

### IPv4 Fragment Header Fields

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Identification|R|D|M| Fragment Offset   | Protocol            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Identification**: 16-bit unique identifier for fragments of same datagram
- **Fragment Offset**: 13-bit offset in 8-byte units
- **M Flag (More Fragments)**: 1 = more fragments follow, 0 = last fragment
- **D Flag**: Don't Fragment (if set, drop if fragmented)

### IPv4 Defragmentation Process

1. Check if packet is a fragment (`offset != 0` or `MF = 1`)
2. If not a fragment, return `XDP_PASS` immediately
3. Look up existing `frag_entry` by `(src_ip, dst_ip, ip_id, protocol, 4)`
4. If no entry exists:
   - Create new `frag_entry`
   - Store fragment data in `frag_buffers`
   - Return `XDP_PASS` (waiting for more fragments)
5. If entry exists:
   - Add fragment to existing entry
   - If all fragments received (`MF = 0` and expected count reached):
     - Reassemble packet
     - Process as complete packet
     - Return `XDP_PASS`
   - Else: Return `XDP_PASS` (waiting for more)

## IPv6 Extension Header Traversal

### Extension Header Types (RFC 8200)

| Next Header | Extension Header |
|-------------|-----------------|
| 0 | Hop-by-Hop Options |
| 43 | Routing |
| 44 | Fragment |
| 50 | ESP |
| 51 | AH |
| 60 | Destination Options |

### Traversal Process

The `parse_ipv6()` function in `nids_bpf.c` implements IPv6 extension header traversal:

```c
/* Extension header types to skip */
while (nexthdr == 0 || nexthdr == 43 || nexthdr == 44 ||
       nexthdr == 50 || nexthdr == 51 || nexthdr == 60) {
    struct ipv6_opt_hdr *opt_hdr = (struct ipv6_opt_hdr *)hdr;

    nexthdr = opt_hdr->nexthdr;
    /* Extension header length is in 8-byte units, plus the 8-byte header itself */
    __u8 ext_len = (nexthdr == 44) ? 8 : (opt_hdr->hdrlen + 1) * 8;
    hdr = (__u8 *)hdr + ext_len;
}
```

Key points:
- Each extension header contains a `nexthdr` field pointing to the next header
- Hop-by-Hop (0), Routing (43), Destination Options (60): `hdrlen + 1` gives length in 8-byte units
- Fragment header (44): Fixed 8-byte length
- ESP (50) and AH (51): Cannot be parsed in XDP (encrypted payload)

### is_ipv6_fragment() Fix

The `is_ipv6_fragment()` function was updated to correctly identify IPv6 fragments:

```c
static __always_inline int is_ipv6_fragment(struct ipv6hdr *ipv6,
                                            void *data_end,
                                            __u8 **next_header,
                                            int *header_len) {
    __u8 nexthdr = ipv6->nexthdr;
    void *hdr = (void *)(ipv6 + 1);
    int len = sizeof(struct ipv6hdr);

    /* Simple extension header parsing - only handles fragments */
    if (nexthdr == 44) {  /* IPv6-Frag */
        struct frag_hdr *frag = (struct frag_hdr *)hdr;
        if ((void *)(frag + 1) > data_end)
            return 0;
        *next_header = (__u8 *)frag + sizeof(struct frag_hdr);
        *header_len = len + sizeof(struct frag_hdr);
        return 1;
    }

    return 0;
}
```

**Bug Fixed**: The original implementation only checked for fragment header at the first position after IPv6 base header. The fix uses proper extension header traversal to find the Fragment header anywhere in the header chain.

## IPv6 Fragment Handling

### IPv6 Fragment Header (RFC 8200)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |  Reserved     |  Fragment Offset    |Res|M|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Identification                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Next Header**: Protocol of the fragment
- **Fragment Offset**: 13-bit offset in 8-byte units
- **M Flag**: More fragments (1 = more, 0 = last)
- **Identification**: 32-bit unique identifier

### IPv6 Defragmentation Process

1. Call `is_ipv6_fragment()` to check for Fragment header via extension header traversal
2. If not a fragment, return `XDP_PASS` immediately
3. Look up existing `frag_entry` by `(src_ip, dst_ip, ip_id, nexthdr, 6)`
4. Similar to IPv4 process but uses 32-bit identification and proper extension header parsing

### IPv6 Fragment Key Computation

IPv6 addresses (128-bit) are folded into 32-bit keys for the frag_track map:

```c
__u32 *src_ip_arr = (__u32 *)ipv6->saddr.in6_u.u6_addr32;
__u32 *dst_ip_arr = (__u32 *)ipv6->daddr.in6_u.u6_addr32;
fkey.src_ip = src_ip_arr[0] ^ (src_ip_arr[1] << 12) ^ (src_ip_arr[2] >> 12) ^ (src_ip_arr[3] << 6);
fkey.dst_ip = dst_ip_arr[0] ^ (dst_ip_arr[1] << 12) ^ (dst_ip_arr[2] >> 12) ^ (dst_ip_arr[3] << 6);
```

## Limitations

### Hard Limits

| Limit | Value | Reason |
|-------|-------|--------|
| Max concurrent reassemblies | 1,024 | `frag_track` max_entries |
| Max fragment buffers | 16,384 | `frag_buffers` max_entries |
| Max fragments per reassembly | 8 | `MAX_FRAGMENTS` constant |
| Reassembly timeout | 30 seconds | `FRAG_TIMEOUT_NS` |
| Max reassembled size | 65,535 bytes | IP maximum |

### Resource Management

- **LRU eviction**: Both `frag_track` and `frag_buffers` use `BPF_MAP_TYPE_LRU_HASH`
- Old reassemblies are automatically evicted when limits are reached
- Fragment data is deleted when parent `frag_entry` is deleted

### Eviction Policy

When `frag_track` is full:
1. LRU algorithm evicts least recently used entry
2. Associated fragment buffers are also deleted
3. New fragment reassembly begins

## Security Considerations

### Fragment Attack Vectors

| Attack Type | Mitigation |
|-------------|------------|
| Fragment overlap | Last-fragment-wins (current), but limited to 8 fragments |
| Tiny fragment attack | Minimum 8-byte fragment size enforced |
| Fragment timeout DoS | 30-second timeout prevents indefinite holding |
| Memory exhaustion | LRU hash limits concurrent reassemblies |

### Dropped Fragments

Fragments are dropped if:
- More than 8 fragments in a datagram
- Fragment data exceeds `FRAG_BUFFER_SIZE` (truncated)
- Timeout exceeded (30 seconds since first fragment)
- Identification conflict in full `frag_track`

## Userspace Reassembly (EVENT_FRAG_REASSEMBLE)

For complex reassembly that cannot be done in eBPF:

1. Kernel sends `EVENT_FRAG_REASSEMBLE` via ringbuf
2. Userspace performs full reassembly
3. Userspace applies DPI rules to complete payload

## Performance Impact

- Fragment handling adds per-packet overhead
- Memory usage grows with concurrent reassemblies
- Batch processing not available for fragments
