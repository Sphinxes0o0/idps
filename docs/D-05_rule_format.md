# D-05: Rule File Format Complete Documentation

This document describes the complete rule file format supported by the IDPS system.

## Rule Format

```
<id> <proto> <dst_port> "<content>" "<message>" [tls_version=<hex>] [sni="<pattern>"] [cipher=<hex>]
```

### Fields

| Field | Type | Required | Description |
|-------|------|---------|-------------|
| `id` | Integer | Yes | Unique rule identifier (positive integer) |
| `proto` | String | Yes | Protocol: `tcp`, `udp`, `icmp`, `any` (or `6`, `17`, `1`, `0`) |
| `dst_port` | Integer or Range | Yes | Port number, `port:port` range, or `any`/`0` |
| `content` | String | No | Substring to match (empty = match all on proto/port) |
| `message` | String | Yes | Alert description (displayed in logs) |
| `tls_version` | Hex | No | Match weak TLS version (e.g., `0x0301`) |
| `sni` | String | No | Match SNI hostname substring |
| `cipher` | Hex | No | Match TLS cipher suite (e.g., `0x0005`) |

## Rule Categories

### Simple Rules (Kernel-Only)

Rules with empty `content` and no TLS options are pushed to the eBPF kernel for fast proto/port matching.

**Format**:
```
<id> <proto> <dst_port> "" "<message>"
```

**Example**:
```
100 tcp 80 "" "HTTP traffic detected"
200 tcp 443 "" "HTTPS traffic detected"
300 udp 53 "" "DNS traffic detected"
```

### Content Rules (User-Space DPI)

Rules with `content`, `tls_version`, `sni`, or `cipher` require user-space BMH pattern matching via AF_XDP.

**Format**:
```
<id> <proto> <dst_port> "<content>" "<message>"
```

**Example**:
```
1000 tcp 80 "GET /admin" "Admin panel access attempt"
1001 tcp 80 "SELECT * FROM" "SQL injection attempt"
1002 tcp 443 "evilsite.com" "Connection to blocked hostname"
```

### TLS Rules

**Format**:
```
<id> <proto> <dst_port> "<content>" "<message>" [tls_option]
```

**TLS Options**:

| Option | Format | Description | Example |
|--------|--------|-------------|---------|
| `tls_version` | `0x0301` (hex) | Match weak TLS version | `tls_version=0x0301` (TLS 1.0) |
| `sni` | `"pattern"` | Match SNI hostname substring | `sni="malware"` |
| `cipher` | `0x0005` (hex) | Match weak cipher suite | `cipher=0x0005` (RC4) |

**Example TLS Rules**:
```
2000 tcp 443 "" "Weak TLS 1.0 detected" tls_version=0x0301
2001 tcp 443 "" "TLS 1.1 detected" tls_version=0x0302
2002 tcp 443 "" "Blocked SNI: malware" sni="malware"
2003 tcp 443 "" "Weak cipher RC4" cipher=0x0005
```

## Protocol Values

| String | Number | Description |
|--------|--------|-------------|
| `tcp` | `6` | TCP protocol |
| `udp` | `17` | UDP protocol |
| `icmp` | `1` | ICMP protocol |
| `any` | `0` | Any protocol |

## Port Specifications

### Single Port
```
100 tcp 80 "" "HTTP traffic"
```

### Port Range
```
100 tcp 80:90 "" "HTTP alternate ports"
```
Matches ports 80, 81, 82, ..., 90.

### Any Port
```
100 tcp any "" "Any TCP traffic"
100 tcp 0 "" "Any TCP traffic"
```

## Complete Examples

### Basic Rules
```
# HTTP detection
100 tcp 80 "" "HTTP traffic on port 80"

# HTTPS detection
200 tcp 443 "" "HTTPS traffic on port 443"

# DNS detection
300 udp 53 "" "DNS query traffic"

# IMCP detection
400 icmp any "" "ICMP traffic"
```

### Content Matching Rules
```
# SQL injection detection
1000 tcp 80 "SELECT * FROM users" "SQL injection attempt"
1001 tcp 80 "UNION SELECT" "SQL injection UNION attack"
1002 tcp 80 "'; DROP TABLE" "SQL injection DROP attempt"

# Command injection
1100 tcp 80 "/etc/passwd" "Local file inclusion attempt"
1101 tcp 80 "| cat /etc/" "Command injection via pipe"

# Web attacks
1200 tcp 80 "<script>" "XSS attempt via script tag"
1201 tcp 80 "eval(" "JavaScript eval attempt"
```

### Port Range Rules
```
# SMB traffic
1300 tcp 445 "" "SMB traffic on standard port"
1301 tcp 139 "" "SMB traffic on legacy port"

# SMB range (ports 139-445)
1302 tcp 139:445 "" "SMB traffic on any port"
```

### TLS Version Rules
```
# Detect weak TLS versions
2000 tcp 443 "" "SSL 3.0 detected" tls_version=0x0300
2001 tcp 443 "" "TLS 1.0 detected" tls_version=0x0301
2002 tcp 443 "" "TLS 1.1 detected" tls_version=0x0302
```

### TLS SNI Rules
```
# Block specific hostnames
2100 tcp 443 "" "Blocked SNI: malware.com" sni="malware.com"
2101 tcp 443 "" "Blocked SNI: phishing" sni="phishing"
2102 tcp 443 "" "Blocked SNI: c2" sni="c2.malicious"

# Block suspicious patterns
2103 tcp 443 "" "Suspicious SNI: exfil" sni="exfil"
```

### TLS Cipher Rules
```
# Block weak ciphers (RC4 family)
2200 tcp 443 "" "RC4 cipher detected" cipher=0x0005
2201 tcp 443 "" "RC4 export cipher" cipher=0x0027
2202 tcp 443 "" "RC4 40-bit export" cipher=0x0003
```

### Combined Rules
```
# TLS 1.0 with specific cipher
3000 tcp 443 "GET /api" "Deprecated TLS with data exfil" tls_version=0x0301 cipher=0x0005
```

## Comments and Whitespace

- Lines starting with `#` are comments
- Empty lines are ignored
- Fields must be separated by whitespace
- Content and message strings must be quoted

**Example with Comments**:
```
# ============================================
# Network Detection Rules
# ============================================

# HTTP traffic
100 tcp 80 "" "HTTP traffic detected"

# SQL Injection
1000 tcp 80 "SELECT * FROM" "SQL injection attempt"
```

## Rule Processing

### Simple Rules (eBPF Kernel)
1. Packet arrives at XDP
2. Extract 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
3. Hash lookup via `rule_index` for O(1) match
4. If matched: send event via ringbuf
5. Optional: drop packet if action=drop

### Content Rules (User-Space AF_XDP)
1. Kernel detects proto/port match
2. Sends `DPI_REQUEST` event via ringbuf
3. User-space receives event
4. AF_XDP receives packet via UMEM
5. BMH pattern matching on payload
6. If matched: log alert

### TLS Rules (User-Space)
1. TCP packet reassembled
2. TLS record header parsed (5 bytes)
3. Content type check (must be 22 = handshake)
4. Version, SNI, cipher extracted
5. Match against TLS rules
6. If matched: log alert

## Rule Limits

| Parameter | Value | Description |
|-----------|-------|-------------|
| `MAX_RULES` | 50,000 | Maximum rules in map |
| `MAX_RULES_TO_CHECK` | 256 | Max rules scanned linearly |
| Rule ID | 0 - 2^31-1 | 31-bit positive integer |

## Error Handling

Invalid rules are logged and skipped:
```
[RULE] rule 1234 at line 56 has invalid port: ignored
[RULE] line 78: invalid tls_version value: xyz - ignored
```

## Best Practices

1. **Use simple rules for common traffic**: Ports 80, 443, 22, 21, 23
2. **Use content rules sparingly**: They require user-space processing
3. **Use TLS rules for compliance**: Detect weak TLS versions/ciphers
4. **Port ranges are expensive**: Prefer specific ports when possible
5. **Order rules by priority**: More specific rules first
6. **Keep rule IDs unique**: Duplicate IDs will overwrite previous rules
