# D-11: Email Protocol Detection

This document describes the email protocol detection functionality for SMTP, POP3, and IMAP protocols.

## Overview

IDPS detects email protocol traffic on well-known ports and can identify specific protocol responses and commands. Email protocol detection helps identify:
- Email servers and their versions
- Potential email-based attacks (spam, phishing relay attempts)
- Unencrypted email traffic security risks

## Technical Implementation

### Detection Architecture

```
+------------------+     +------------------+     +------------------+
|   Port Filter    | --> | Protocol Parser  | --> |   Event Alert   |
|  (25,110,143,   |     | (Banner/Response)|     | (EVENT_EMAIL_*) |
|   465,587,993)  |     |                  |     |                 |
+------------------+     +------------------+     +------------------+
```

### Email Protocol Ports

| Protocol | Port(s) | SSL/TLS | Description |
|----------|---------|---------|-------------|
| SMTP | 25, 465, 587 | 465 (SMTPS), 587 (STARTTLS) | Simple Mail Transfer Protocol |
| POP3 | 110, 995 | 995 (POP3S) | Post Office Protocol v3 |
| IMAP | 143, 993 | 993 (IMAPS) | Internet Message Access Protocol |

### Event Types

| Event Type | Value | Description |
|------------|-------|-------------|
| `EVENT_SMTP_DETECTED` | TBD | SMTP banner/version detected |
| `EVENT_POP3_DETECTED` | TBD | POP3 banner/version detected |
| `EVENT_IMAP_DETECTED` | TBD | IMAP banner/version detected |

## SMTP Detection

### Banner Pattern

SMTP servers typically send a greeting banner on connection:

```
220 mail.example.com ESMTP Postfix
```

**Detection Rules**:
- Port 25, 465, 587
- Payload starts with `220 ` (SMTP service ready response)
- Extract server identification string after `220 `

### Common SMTP Response Codes

| Code | Meaning |
|------|---------|
| 220 | Service ready |
| 250 | Requested mail action okay |
| 354 | Start mail input |
| 421 | Service not available |
| 550 | User not local |
| 554 | Transaction failed |

## POP3 Detection

### Banner Pattern

POP3 servers typically send a greeting banner:

```
+OK POP3 mail.example.com server ready
```

**Detection Rules**:
- Port 110, 995
- Payload starts with `+OK ` (POP3 positive response)
- Extract server identification string after `+OK `

### Common POP3 Response Codes

| Code | Meaning |
|------|---------|
| +OK | Positive response |
| -ERR | Negative response |
| +OK POP3 | Service ready banner |

## IMAP Detection

### Banner Pattern

IMAP servers typically send a greeting banner:

```
* OK [CAPABILITY ...] mail.example.com IMAP4rev1 server ready
```

**Detection Rules**:
- Port 143, 993
- Payload starts with `* OK ` (IMAP untagged positive response)
- Extract server identification string after `* OK `

### Common IMAP Response Codes

| Code | Meaning |
|------|---------|
| * OK | Untagged positive response |
| * BYE | Server closing connection |
| * PREAUTH | Pre-authenticated state |

## Configuration

### Rule Format

Email detection rules use the following format in `rules.txt`:

```
# SMTP detection (content matching for server identification)
content="220 "; protocol=tcp; dst_port=25; message="SMTP server detected"

# POP3 detection
content="+OK "; protocol=tcp; dst_port=110; message="POP3 server detected"

# IMAP detection
content="* OK "; protocol=tcp; dst_port=143; message="IMAP server detected"
```

### BMH Content Matching

The Boyer-Moore-Horspool algorithm in AF_XDP userspace DPI performs content matching:
- Fast pattern matching for protocol banners
- Case-insensitive option available
- Supports substring matching

## Implementation Details

### BPF Detection (nids_bpf.c)

The kernel eBPF program detects email protocols via `check_smtp()`, `check_pop3()`, and `check_imap()` functions:

```c
static __always_inline int check_smtp(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    /* Check for "220 " SMTP greeting */
    if (payload[0] == '2' && payload[1] == '2' &&
        payload[2] == '0' && payload[3] == ' ')
        return 1;
    return 0;
}
```

### Userspace AF_XDP Detection

Userspace DPI via AF_XDP provides deeper inspection:
- Full payload analysis
- TLS/STARTTLS detection for encrypted sessions
- Server version fingerprinting

## Limitations and Considerations

### TLS/Encrypted Sessions

Email protocols on ports 465, 587 (SMTP), 995 (POP3), and 993 (IMAP) typically use TLS encryption. Detection capabilities for encrypted traffic:
- Port-based detection still works (traffic volume, connection patterns)
- Content inspection requires TLS decryption (MITM proxy, or passive SSL inspection)
- Certificate-based detection (self-signed, weak ciphers) is possible

### Banner Grepting

Some email servers:
- Suppress or delay banners for security
- Use connection banners that span multiple packets
- Implement pipelining that changes expected patterns

### Evasion Techniques

Attackers may use:
- Banner modification to evade detection
- Protocol tunneling over non-standard ports
- Mixed-case or obfuscated responses

## Security Recommendations

1. **Monitor email ports**: Track all traffic on ports 25, 110, 143, 465, 587, 993, 995
2. **Alert on non-standard ports**: Email traffic on unusual ports may indicate tunneling
3. **Certificate monitoring**: Detect self-signed or expired certificates
4. **TLS version enforcement**: Alert on SSLv3, TLS 1.0, TLS 1.1 usage

## References

- RFC 5321 - Simple Mail Transfer Protocol (SMTP)
- RFC 1939 - Post Office Protocol Version 3 (POP3)
- RFC 3501 - INTERNET MESSAGE ACCESS PROTOCOL - VERSION 4rev1 (IMAP)
- RFC 8314 - Clearance for Email
