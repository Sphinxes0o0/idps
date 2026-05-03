# D-12: DNS Query Extraction

This document describes the DNS query name extraction and DNS tunneling detection functionality.

## Overview

IDPS extracts DNS query names from DNS request packets to enable:
- DNS query logging and monitoring
- DNS tunneling detection
- Domain-based threat intelligence
- DNS amplification attack detection

## Technical Implementation

### DNS Protocol Basics

DNS uses UDP port 53 for most queries. A DNS packet contains:

```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### DNS Query Format

DNS query name encoding (RFC 1035):
- Labels separated by length bytes
- Each label: 1-byte length + label bytes
- Terminated by zero-length label (root)
- Example: `www.example.com` = `3www7example3com0`

## Data Structures

### DNS Query Info (af_xdp.h)

```c
struct DnsQueryInfo {
    std::string query_name;   // Decoded domain name
    uint16_t query_type;     // Query type (A=1, AAAA=28, TXT=16, NULL=10, AXFR=252)
    bool is_response;         // Whether this is a response packet
    uint16_t id;             // DNS Transaction ID
};
```

### DNS Tunneling Tracking

```c
struct DnsTunnelKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

struct DnsTunnelData {
    std::string domain;           // Most common queried domain
    uint32_t query_count;         // Number of queries
    uint32_t total_bytes;         // Total bytes transferred
    uint64_t first_seen;          // First query timestamp
    uint64_t last_seen;           // Last query timestamp
    bool alert_sent;              // Alert already sent
};
```

## DNS Query Extraction

### Extraction Process

1. Identify DNS traffic (UDP port 53)
2. Parse DNS header to extract transaction ID
3. Check QR bit to determine query/response
4. Parse question section to extract:
   - Query name (domain)
   - Query type
   - Query class

### Query Type Detection

| Type | Value | Description |
|------|-------|-------------|
| A | 1 | IPv4 address query |
| AAAA | 28 | IPv6 address query |
| MX | 15 | Mail exchange query |
| TXT | 16 | Text query |
| NS | 2 | Nameserver query |
| CNAME | 5 | Canonical name query |
| SOA | 6 | Start of authority |
| PTR | 12 | Pointer query |
| AXFR | 252 | Zone transfer request |
| * | 255 | All records |

## DNS Tunneling Detection

### Tunneling Overview

DNS tunneling encodes data in DNS queries and responses, enabling:
- Data exfiltration
- Command and control (C2) communication
- Bypassing network restrictions

### Detection Rules

#### Rule 1: High Query Rate

Detects when a single source sends unusual numbers of DNS queries.

```
if (queries_per_minute > THRESHOLD && time_window < 60s) {
    ALERT: Potential DNS tunneling (high query rate)
}
```

**Thresholds**:
- Normal: < 100 queries/minute per source
- Suspicious: 100-500 queries/minute
- High: > 500 queries/minute

#### Rule 2: Long Subdomain Labels

DNS tunneling often uses long random-looking subdomain labels.

```
if (max_label_length > 63) {  // DNS label max is 63 bytes
    ALERT: Suspicious long label in DNS query
}
```

**Example tunneling payload**:
```
longrandomstring1234567890.legitimate-looking.domain.com
```

#### Rule 3: High Byte Count per Query

Tunneling may encode significant data in TXT records or long hostnames.

```
if (query_len > 200 bytes) {
    ALERT: Suspiciously long DNS query
}
```

#### Rule 4: Non-Existent Domains (NXDOMAIN Flood)

Some tunneling techniques flood queries for non-existent domains.

```
if (nxdomain_ratio > 0.5 && query_count > THRESHOLD) {
    ALERT: Potential DNS tunneling (NXDOMAIN flood)
}
```

#### Rule 5: Unusual Query Types

Detection of unusual query type combinations.

```
# AXFR zone transfer detection (should be rare)
if (query_type == AXFR) {
    ALERT: DNS zone transfer request detected
}

# NULL query type (rare, often used in tunneling)
if (query_type == NULL (10)) {
    ALERT: NULL DNS query type detected
}
```

#### Rule 6: Long TXT Response Patterns

DNS tunneling may use TXT records with base64-encoded data.

```
if (response_txt_length > 500 bytes) {
    ALERT: Suspiciously long TXT response
}
```

### DNS Amplification Detection (Related)

DNS amplification uses DNS responses to amplify attack traffic. See D-07 for details.

**Configuration** (nids_common.h):
```c
struct config_entry {
    __u32 dns_amp_threshold;  // Response/query ratio threshold (default: 10x)
};
```

## Implementation Details

### BPF Program (nids_bpf.c)

The kernel eBPF program performs DNS amplification tracking:

```c
static __always_inline int check_dns_amplification(__u32 src_ip, __u32 dst_ip,
                                                   __u16 src_port, __u16 dst_port,
                                                   __u32 pkt_len) {
    // Track query bytes and response bytes
    // Alert if response/query ratio exceeds threshold
}
```

### Userspace DNS Parser (af_xdp.cpp)

Userspace DNS parsing extracts full query names:

```c
bool XdpProcessor::parse_dns_query(const uint8_t* data, size_t len,
                                   DnsQueryInfo& info) {
    // Parse DNS header
    // Extract transaction ID
    // Parse question section
    // Decode domain name
}
```

### DNS Query Name Decoding

Domain names are encoded with length-prefixed labels:

```c
std::string decode_dns_name(const uint8_t* data, size_t& offset) {
    std::string result;
    while (data[offset] != 0) {
        if ((data[offset] & 0xC0) == 0xC0) {
            // Compression pointer - follow reference
            // (not shown for simplicity)
        } else {
            uint8_t label_len = data[offset++];
            result.append((char*)&data[offset], label_len);
            offset += label_len;
            if (data[offset] != 0) result += '.';
        }
    }
    return result;
}
```

## Configuration

### Rule Format

DNS detection rules in `rules.txt`:

```
# Detect DNS zone transfer attempts
dns_query_type=AXFR; severity=HIGH; message="DNS zone transfer request"

# Detect NULL DNS queries (potential tunneling)
dns_query_type=NULL; severity=MEDIUM; message="NULL DNS query type detected"

# Detect long subdomain labels
dns_label_length=63; severity=LOW; message="Long DNS label detected"
```

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dns_tunneling_threshold` | 100 | Queries per minute threshold |
| `dns_label_max_length` | 63 | Maximum label length |
| `dns_query_max_length` | 200 | Maximum query length |
| `dns_amp_threshold` | 10 | Amplification ratio |

## Limitations and Considerations

### Encrypted DNS (DoH/DoT)

DNS over HTTPS (DoH) and DNS over TLS (DoT) encrypt DNS queries:
- eBPF kernel detection cannot inspect encrypted DNS
- Userspace AF_XDP can detect DoH via HTTP host header patterns
- Certificate inspection can help identify DoH providers

### DNS-over-HTTPS Detection

DoH traffic on port 443 may be detected via HTTP patterns:
- `Accept: application/dns-json`
- `Content-Type: application/dns-message`
- HTTP Host header containing known DoH providers

### Fragmented DNS

Large DNS responses may be fragmented:
- IPv4/IPv6 fragmentation is handled by the defragmentation module
- See D-07 for fragment reassembly details

### Performance Considerations

- DNS query extraction adds per-packet overhead
- High query rates may impact processing
- Consider sampling for very high volume scenarios

## Security Recommendations

1. **Monitor DNS query volumes**: Establish baseline for normal query rates
2. **Alert on query type anomalies**: Unusual types like AXFR, NULL may indicate attack
3. **Track high-length queries**: Long domain names may indicate tunneling
4. **Log query names**: For incident response and threat hunting
5. **Block zone transfers**: AXFR requests should be restricted to authorized servers

## References

- RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- RFC 1034 - DOMAIN NAMES - CONCEPTS AND FACILITIES
- RFC 6891 - Extension Mechanisms for DNS (EDNS)
- RFC 8484 - DNS Queries over HTTPS (DoH)
- IANA DNS Parameters Registry
