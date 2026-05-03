# D-09: SecEvent JSON Format Reference

This document describes the JSON format used for security events.

## Overview

`SecEvent` (Security Event) is the core data structure for representing detected security incidents. It is serialized to JSON by the `CommThread` for logging and syslog output.

## JSON Schema

```json
{
  "type": 0,
  "ts": 1714567890123456789,
  "src": "192.168.1.100:54321",
  "dst": "10.0.0.1:443",
  "proto": 6,
  "rule_id": 1001,
  "msg": "SQL injection attempt"
}
```

## Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `type` | integer | Event type (see Event Types) |
| `ts` | integer | Unix timestamp in nanoseconds |
| `src` | string | Source address: `IP:port` |
| `dst` | string | Destination address: `IP:port` |
| `proto` | integer | IP protocol number (see Protocol Numbers) |
| `rule_id` | integer | Matched rule ID (-1 if N/A) |
| `msg` | string | Human-readable message (max 95 chars) |

## Event Types

### Type Values

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | `RULE_MATCH` | Snort-like rule matched |
| 1 | `DDOS` | DDoS threshold exceeded |
| 2 | `FLOW_THRESHOLD` | Flow threshold exceeded |
| 3 | `NEW_FLOW` | New flow created |
| 4 | `DPI_REQUEST` | Needs user-space content inspection |
| 5 | `SYN_FLOOD` | SYN flood detected |
| 6 | `ICMP_FLOOD` | ICMP flood detected |
| 7 | `DNS_AMP` | DNS amplification attack detected |
| 8 | `HTTP_DETECTED` | HTTP banner/response detected |
| 9 | `SSH_BANNER` | SSH protocol banner detected |
| 10 | `FTP_CMD` | FTP command detected |
| 11 | `TELNET_OPT` | Telnet option negotiation detected |
| 12 | `PORT_SCAN` | Port scan detected |
| 13 | `FRAG_REASSEMBLE` | Fragment reassembly complete |
| 14 | `ACK_FLOOD` | TCP ACK flood detected |
| 15 | `FIN_FLOOD` | TCP FIN flood detected |
| 16 | `RST_FLOOD` | TCP RST flood detected |
| 17 | `PROCESS_CONNECT` | Process connect() syscall |
| 18 | `PROCESS_CLOSE` | Process close() syscall |
| 19 | `SMTP_DETECTED` | SMTP protocol detected |
| 20 | `POP3_DETECTED` | POP3 protocol detected |
| 21 | `IMAP_DETECTED` | IMAP protocol detected |

### Type Mappings to Syslog Priority

| Event Type | Syslog Priority |
|------------|----------------|
| `DDOS` | `LOG_ERR` |
| `RULE_MATCH` | `LOG_WARNING` |
| All others | `LOG_INFO` |

## Protocol Numbers

| Value | Protocol | String |
|-------|----------|--------|
| 0 | Any/None | `any` |
| 1 | ICMP | `icmp` |
| 6 | TCP | `tcp` |
| 17 | UDP | `udp` |

## Example Events

### Rule Match Event

```json
{
  "type": 0,
  "ts": 1714567890123456789,
  "src": "192.168.1.100:54321",
  "dst": "10.0.0.1:80",
  "proto": 6,
  "rule_id": 1001,
  "msg": "SQL injection attempt"
}
```

### SYN Flood Alert

```json
{
  "type": 5,
  "ts": 1714567890123456789,
  "src": "10.0.0.1:0",
  "dst": "192.168.1.1:80",
  "proto": 6,
  "rule_id": -1,
  "msg": "SYN flood detected"
}
```

### New Flow Event

```json
{
  "type": 3,
  "ts": 1714567890123456789,
  "src": "192.168.1.100:12345",
  "dst": "10.0.0.1:443",
  "proto": 6,
  "rule_id": -1,
  "msg": "New HTTPS flow"
}
```

### HTTP Detection

```json
{
  "type": 8,
  "ts": 1714567890123456789,
  "src": "192.168.1.100:54321",
  "dst": "10.0.0.1:80",
  "proto": 6,
  "rule_id": -1,
  "msg": "HTTP response detected"
}
```

### Port Scan Alert

```json
{
  "type": 12,
  "ts": 1714567890123456789,
  "src": "192.168.1.200:0",
  "dst": "10.0.0.1:0",
  "proto": 6,
  "rule_id": -1,
  "msg": "Port scan detected"
}
```

## Event Source

### Kernel Events (from eBPF Ringbuf)

These events are generated in the kernel and sent via the `events` ringbuf:
- DDoS alerts (SYN flood, ICMP flood, etc.)
- Rule matches
- Port scan detection
- Protocol detection (HTTP, SSH, FTP, Telnet)

### Userspace Events (from AF_XDP/CommThread)

These events are generated in userspace after DPI:
- Content rule matches (BMH)
- TLS weak version/cipher/SNI matches

## Serialization Implementation

```cpp
// From src/ipc/event_queue.cpp
std::string SecEvent::to_json() const {
    char src[INET_ADDRSTRLEN] = {};
    char dst[INET_ADDRSTRLEN] = {};
    uint32_t src_n = htonl(src_ip);
    uint32_t dst_n = htonl(dst_ip);
    inet_ntop(AF_INET, &src_n, src, sizeof(src));
    inet_ntop(AF_INET, &src_n, dst, sizeof(dst));

    char buf[512];
    int len = std::snprintf(buf, sizeof(buf),
        R"({"type":%d,"ts":%llu,"src":"%s:%u","dst":"%s:%u","proto":%u,"rule_id":%d,"msg":"%s"})",
        static_cast<int>(type),
        static_cast<unsigned long long>(timestamp),
        src, static_cast<unsigned>(src_port),
        dst, static_cast<unsigned>(dst_port),
        static_cast<unsigned>(ip_proto),
        rule_id,
        message);

    return len > 0 ? std::string(buf, static_cast<size_t>(len)) : "{}";
}
```

## Log Output

Events are written to:
1. **File**: `/tmp/events.json` (or configured path)
2. **Syslog**: System logging daemon (if enabled)

### File Format

Each event is a single-line JSON string:
```
{"type":0,"ts":1714567890123456789,"src":"192.168.1.100:54321","dst":"10.0.0.1:80","proto":6,"rule_id":1001,"msg":"SQL injection attempt"}
{"type":5,"ts":1714567890123456790,"src":"10.0.0.1:0","dst":"192.168.1.1:80","proto":6,"rule_id":-1,"msg":"SYN flood detected"}
```

### jq Examples

```bash
# Filter by event type
jq 'select(.type == 0)' events.json

# Filter by source IP
jq 'select(.src | startswith("192.168."))' events.json

# Count events by type
jq -s 'group_by(.type) | map({type: .[0].type, count: length})' events.json

# Find SYN floods
jq 'select(.type == 5)' events.json
```

## Limitations

- IPv4 only (IPv6 addresses not fully supported in current `SecEvent`)
- Message field limited to 95 characters
- Port 0 used when protocol is not TCP/UDP (e.g., ICMP, raw IP)
