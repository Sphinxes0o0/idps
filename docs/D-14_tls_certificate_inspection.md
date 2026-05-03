# D-14: TLS Certificate Inspection

This document describes the TLS certificate inspection functionality for detecting weak TLS configurations, expired certificates, and certificate-based threats.

## Overview

IDPS performs TLS certificate inspection to detect:
- Weak TLS versions (SSLv3, TLS 1.0, TLS 1.1)
- Weak cipher suites
- Expired or self-signed certificates
- Certificate hostname mismatches
- Potentially malicious TLS patterns (certificate pinning bypass, etc.)

## Technical Implementation

### TLS Protocol Basics

TLS Record Structure:
```
+--------+--------+--------+--------+--------+--------+--------+--------+
| Content Type (1) |   TLS Version (2)   |        Length (2)        |
+------------------+---------------------+--------------------------+
|                         Fragment Data                          |
+----------------------------------------------------------------+
```

TLS Handshake Types:
- 0x01: ClientHello
- 0x02: ServerHello
- 0x0B: Certificate (Server Certificate)
- 0x0C: ServerKeyExchange
- 0x0D: CertificateRequest
- 0x0E: ServerHelloDone
- 0x10: ClientKeyExchange
- 0x14: Finished

## TLS Version Detection

### Weak TLS Versions

| Version | Value | Status |
|---------|-------|--------|
| SSL 3.0 | 0x0300 | Deprecated (POODLE) |
| TLS 1.0 | 0x0301 | Deprecated (BEAST) |
| TLS 1.1 | 0x0302 | Deprecated (BEAST) |
| TLS 1.2 | 0x0303 | Acceptable |
| TLS 1.3 | 0x0304 | Recommended |

### Version Detection Rules

```c
// TLS version constants (af_xdp.cpp)
static constexpr uint16_t TLS_VERSION_SSL3 = 0x0300;
static constexpr uint16_t TLS_VERSION_TLS1_0 = 0x0301;
static constexpr uint16_t TLS_VERSION_TLS1_1 = 0x0302;
static constexpr uint16_t TLS_VERSION_TLS1_2 = 0x0303;
static constexpr uint16_t TLS_VERSION_TLS1_3 = 0x0304;

// Weak version detection
if (version == TLS_VERSION_SSL3 || version == TLS_VERSION_TLS1_0 ||
    version == TLS_VERSION_TLS1_1) {
    info.weak_version = true;
}
```

### Rule Format

```
# Detect weak TLS version
tls_version=0x0301; severity=HIGH; message="Weak TLS 1.0 detected"
tls_version=0x0300; severity=CRITICAL; message="Deprecated SSL 3.0 detected"
```

## TLS Cipher Suite Detection

### Weak Cipher Suites

| Cipher | Value | Weakness |
|--------|-------|----------|
| TLS_RSA_WITH_RC4_128_SHA | 0x0005 | RC4 is broken |
| TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA | 0x0027 | Export-grade cipher |
| TLS_RSA_EXPORT_WITH_RC4_40_MD5 | 0x0003 | Export-grade, MD5 |
| TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 | 0x0006 | Export-grade |
| TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA | 0x0011 | Export-grade |

### Cipher Suite Detection Rules

```c
// Weak ciphers array (af_xdp.cpp)
static constexpr uint16_t WEAK_CIPHERS[] = {
    0x0005, /* TLS_RSA_WITH_RC4_128_SHA */
    0x0027, /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
    0x0003, /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
    0x0006, /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
    0x0011, /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
};
```

### Rule Format

```
# Detect weak cipher suites
cipher=0x0005; severity=HIGH; message="Weak RC4 cipher suite detected"
cipher=0x0027; severity=MEDIUM; message="Weak export-grade cipher detected"
```

## TLS Certificate Parsing

### Certificate Structure (X.509)

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   AlgorithmIdentifier,
    signatureValue       BIT STRING
}

TBSCertificate ::= SEQUENCE {
    version         [0]  EXPLICIT Version DEFAULT v1,
    serialNumber         CertificateSerialNumber,
    signature            AlgorithmIdentifier,
    issuer               Name,
    validity             Validity,
    subject              Name,
    subjectPublicKeyInfo SubjectPublicKeyInfo,
    ...
}
```

### Extracted Certificate Fields

The system extracts the following fields from X.509 certificates:

| Field | Description |
|-------|-------------|
| `issuer` | Certificate Authority that issued the certificate |
| `subject` | Entity the certificate belongs to |
| `common_name` | Primary name (CN) of the subject |
| `sans` | Subject Alternative Names (DNS names, IPs) |
| `not_before` | Certificate validity start timestamp |
| `not_after` | Certificate validity end timestamp |
| `self_signed` | Whether issuer == subject |
| `expired` | Whether current time > not_after |
| `weak_hash` | Whether MD5 or SHA1 is used |

### Certificate Data Structure

```c
struct TlsCertInfo {
    std::string issuer;        // Certificate issuer (CN)
    std::string subject;       // Certificate subject (CN)
    std::string common_name;   // Common Name (CN)
    std::vector<std::string> sans;  // Subject Alternative Names
    uint64_t not_before;      // Validity start (epoch seconds)
    uint64_t not_after;       // Validity end (epoch seconds)
    bool self_signed;         // Issuer == Subject
    bool expired;            // Current time > not_after
    bool weak_hash;          // MD5 or SHA1 signature
};
```

## TLS 0-RTT Early Data Detection (F-22)

### 0-RTT Overview

TLS 1.3 introduced 0-RTT (early data) which allows data transmission before the handshake completes. This enables faster connection establishment but has replay attack risks.

### Detection

```c
// TLS extension types
static constexpr uint8_t TLS_EXT_EARLY_DATA = 42;

// Detection in parse_tls_record()
if (ext_type == TLS_EXT_EARLY_DATA) {
    info.early_data = true;
}

// Alert generation
if (tls.early_data && tls.handshake_type == TLS_HANDSHAKE_CLIENT_HELLO) {
    // Generate alert for 0-RTT early data
    result.message = "TLS 0-RTT early data detected (replay attack risk)";
}
```

### Rule Format

```
# Detect TLS 0-RTT early data
early_data=1; severity=MEDIUM; message="TLS 0-RTT early data detected"
```

## SNI (Server Name Indication) Detection

### SNI Overview

SNI allows clients to specify the hostname they want to connect to during the TLS handshake. This enables server-side certificate selection for virtual hosting.

### SNI Extraction

```c
// SNI extension type
static constexpr uint8_t TLS_EXT_SNI = 0;

// Extract SNI from ClientHello
while (offset + 4 < ext_end) {
    uint16_t ext_type = (handshake[offset] << 8) | handshake[offset + 1];
    uint16_t ext_len = (handshake[offset + 2] << 8) | handshake[offset + 3];

    if (ext_type == TLS_EXT_SNI) {
        // Parse SNI list and hostname
        std::string sni_hostname = extract_sni(handshake + offset + 4, ext_len);
    }
}
```

### SNI Blocklist Rules

```
# Block known malicious domains via SNI
sni="malware-c2.example.com"; severity=HIGH; message="Malicious C2 domain detected"

# Block suspicious patterns
sni=".onion"; severity=HIGH; message="Tor hidden service detected"
```

## TLS Record Fragmentation Handling (E-24)

### Fragmentation Overview

TLS records may be fragmented across multiple TCP packets. The system reassembles fragments before parsing.

### Fragment Tracking

```c
struct TlsFragmentKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

struct TlsFragmentData {
    std::vector<uint8_t> data;  // Accumulated TLS record data
    uint32_t expected_len;       // Expected total TLS record length
    uint64_t first_seen;         // Timestamp for timeout
};
```

### Reassembly Process

1. Check if we have a partial TLS record for this flow
2. If yes, append new data to existing buffer
3. Check if we have complete record (5 + length bytes)
4. If complete, parse the TLS record
5. If incomplete and buffer exceeds limit, discard
6. Timeout old fragments after 5 seconds

## Implementation Details

### TLS Record Parsing (af_xdp.cpp)

```c
bool XdpProcessor::parse_tls_record(const uint8_t* data, size_t len, TlsInfo& info) {
    // TLS record header: content_type(1) + version(2) + length(2) = 5 bytes
    if (len < 5) return false;

    uint8_t content_type = data[0];
    uint16_t version = (data[1] << 8) | data[2];

    if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) return false;

    info.is_tls = true;
    info.version = version;

    // Weak version check
    if (version == TLS_VERSION_SSL3 || version == TLS_VERSION_TLS1_0 ||
        version == TLS_VERSION_TLS1_1) {
        info.weak_version = true;
    }

    // Parse handshake body...
}
```

### Detection Callback

```c
void XdpProcessor::detect_tls(const XdpPacket& pkt, const uint8_t* payload, size_t payload_len) {
    // Check for weak TLS version
    if (tls.weak_version) {
        for (const auto& rule : tls_version_rules_) {
            if (rule.version == tls.version) {
                // Generate alert via dpi_callback_
            }
        }
    }

    // Check SNI against blocklist
    if (!tls.sni.empty()) {
        for (const auto& rule : sni_rules_) {
            if (sni_lower.find(rule.pattern) != std::string::npos) {
                // Generate alert
            }
        }
    }

    // Check cipher suite
    if (tls.cipher_suite != 0) {
        for (const auto& rule : cipher_rules_) {
            if (rule.cipher == tls.cipher_suite) {
                // Generate alert
            }
        }
    }
}
```

## Configuration

### Rule Format

TLS detection rules in `rules.txt`:

```
# Weak TLS versions
tls_version=0x0301; severity=HIGH; message="Weak TLS 1.0 detected"
tls_version=0x0300; severity=CRITICAL; message="Deprecated SSL 3.0 detected"

# Weak cipher suites
cipher=0x0005; severity=HIGH; message="RC4 cipher detected"
cipher=0x0027; severity=MEDIUM; message="Export-grade cipher"

# SNI blocklist
sni="malware-c2.example.com"; severity=HIGH; message="Malicious domain"
sni=".onion"; severity=MEDIUM; message="Tor hidden service"

# Certificate rules
cert_expired=1; severity=LOW; message="Expired certificate detected"
cert_self_signed=1; severity=LOW; message="Self-signed certificate"
```

### Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `tls_frag_timeout_ms` | 5000 | TLS fragment reassembly timeout |
| `tls_max_fragments` | 16 | Maximum fragments per record |
| `tls_min_version` | 0x0303 | Minimum acceptable TLS version |

## Limitations and Considerations

### TLS 1.3 Encrypted Extensions

TLS 1.3 encrypts more of the handshake, including:
- Certificate (encrypted in 1.3)
- Extensions beyond SNI
- Signature algorithms

Detection capabilities are reduced for TLS 1.3 encrypted content.

### Perfect Forward Secrecy (PFS)

When PFS is used, session keys cannot be derived from captured traffic. Certificate inspection still works.

### Certificate Pinning

Some applications use certificate pinning which may cause:
- False positives for legitimate apps with pinned certs
- Detection evasion if pinning is bypassed

### Mutual TLS (mTLS)

mTLS involves client certificates which may contain:
- Additional certificate fields to inspect
- Client authentication information

## Security Recommendations

1. **Enforce TLS 1.2+**: Disable SSL 3.0, TLS 1.0, TLS 1.1
2. **Block weak ciphers**: RC4, export-grade ciphers should be rejected
3. **Monitor SNI blocklist**: Check against known malicious domains
4. **Alert on self-signed certs**: May indicate MITM attack
5. **Alert on expired certs**: May indicate misconfiguration or attack
6. **Monitor 0-RTT usage**: Log for security review (replay risk)

## References

- RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3
- RFC 5246 - The Transport Layer Security (TLS) Protocol Version 1.2
- RFC 4346 - The Transport Layer Security (TLS) Protocol Version 1.1
- RFC 2246 - The TLS Protocol Version 1.0
- RFC 7525 - Recommendations for Secure Use of TLS and DTLS
- Mozilla TLS Guidelines
- IANA TLS Cipher Suites Registry
