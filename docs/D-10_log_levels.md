# D-10: Log Level Reference

This document describes the logging levels used throughout the IDPS system.

## Log Levels

| Level | Value | Constant | Use Case |
|-------|-------|----------|----------|
| TRACE | 0 | `LogLevel::TRACE` | Detailed debugging information |
| DEBUG | 1 | `LogLevel::DEBUG` | Debugging messages |
| INFO | 2 | `LogLevel::INFO` | Informational messages |
| WARN | 3 | `LogLevel::WARN` | Warning conditions |
| ERR | 4 | `LogLevel::ERR` | Error conditions |
| OFF | 5 | `LogLevel::OFF` | No logging |

## Level Hierarchy

```
TRACE < DEBUG < INFO < WARN < ERR < OFF
```

When a log level is set, all levels at or below that level are output.

**Example:** If `INFO` is set, then `TRACE`, `DEBUG`, and `INFO` messages are output.

## Log Macros

### Macro Definitions

```cpp
#define LOG_TRACE(tag, ...)  // Trace level logging
#define LOG_DEBUG(tag, ...)   // Debug level logging
#define LOG_INFO(tag, ...)    // Info level logging
#define LOG_WARN(tag, ...)    // Warning level logging
#define LOG_ERR(tag, ...)     // Error level logging
```

### Usage Pattern

```cpp
LOG_INFO("xdp", "opened AF_XDP on %s queue %u", iface.c_str(), queue_id);
LOG_ERR("xdp", "failed to create socket: %s", strerror(errno));
LOG_DEBUG("dpi", "packet processed: %u bytes", len);
```

## Level Usage Guidelines

### TRACE (Level 0)

**Purpose:** Extremely detailed information for troubleshooting deep issues.

**Use for:**
- Function entry/exit points
- Loop iterations in critical paths
- Variable state dumps
- Performance measurement markers

**Example:**
```cpp
LOG_TRACE("xdp", "enter process_packets(), frame_count=%d", frame_count);
```

**Impact:** Very high volume output. Use only when debugging.

### DEBUG (Level 1)

**Purpose:** Development and troubleshooting information.

**Use for:**
- Configuration values at startup
- Map statistics
- Event counts
- Rule loading information
- Connection tracking updates

**Example:**
```cpp
LOG_DEBUG("ebpf", "loaded %zu rules, %zu DPI rules", rules.size(), dpi_rules);
```

**Impact:** High volume output in production. Not recommended for production.

### INFO (Level 2)

**Purpose:** Normal operational information.

**Use for:**
- Application startup/shutdown
- Interface attachment
- Configuration changes
- Statistics summaries (periodically)
- Protocol detection events

**Example:**
```cpp
LOG_INFO("app", "IDPS started on interface %s", iface.c_str());
LOG_INFO("app", "shutdown complete, events written: %lu", events_written_);
```

**Impact:** Moderate output. Safe for production.

### WARN (Level 3)

**Purpose:** Warning conditions that may need attention.

**Use for:**
- Non-fatal errors
- Resource exhaustion approaching limits
- Rule parsing warnings
- Configuration issues
- Rate limiting triggered

**Example:**
```cpp
LOG_WARN("rules", "rule %d has invalid port: ignored", rule_id);
LOG_WARN("dpi", "UMEM exhausted, dropping packet");
```

**Impact:** Low volume. Investigate warnings in production logs.

### ERR (Level 4)

**Purpose:** Error conditions that prevent operations.

**Use for:**
- Failed operations (socket creation, map allocation)
- Critical errors (out of memory)
- Fatal conditions (XDP attachment failed)
- Security alerts (DDoS detected)

**Example:**
```cpp
LOG_ERR("xdp", "failed to register UMEM: %s", strerror(errno));
LOG_ERR("ddos", "SYN flood detected from %s", src_ip_str);
```

**Impact:** Should never occur in healthy production. Always investigate.

## Tag System

Each log message includes a tag to categorize the source:

| Tag | Component | Description |
|-----|-----------|-------------|
| `app` | NidsApp | Main application |
| `xdp` | XdpProcessor | AF_XDP processing |
| `ebpf` | EbpfLoader | eBPF loader |
| `rules` | RuleParser | Rule parsing |
| `dpi` | BMH Search | Deep packet inspection |
| `ddos` | DDoS Detection | DDoS mitigation |
| `frag` | Fragmentation | Fragment reassembly |
| `net` | Network | Network events |

## Setting Log Levels

### Runtime Configuration

```cpp
#include "core/logger.h"

// Set by name
nids::log_set_level("debug");  // "trace", "debug", "info", "warn", "error", "off"

// Check current level
if (nids::g_log_level.load() <= nids::LogLevel::INFO) {
    // Only log if INFO or lower
}
```

### Command Line

```bash
# With debug logging
sudo ./build/bin/nids eth0 rules.txt /tmp/events.json debug

# Info level (default)
sudo ./build/bin/nids eth0 rules.txt /tmp/events.json info
```

### Configuration File

```json
{
  "interface": "eth0",
  "rules_file": "rules.txt",
  "log_level": "info"
}
```

## Output Destinations

### Console Output

By default, logs are written to stdout.

### File Output

```bash
./build/bin/nids eth0 rules.txt /tmp/events.json  # Events to file
./build/bin/nids eth0 rules.txt -                 # Events to stdout
```

### Syslog Integration

When `use_syslog: true` is configured, logs are sent to the system logger:

```json
{
  "use_syslog": true
}
```

Syslog facilities used:
- `LOG_USER` facility
- Priority based on event type (see D-09)

## Log Volume Estimates

Assuming 1000 events/second:

| Level | Events/Second | MB/Day |
|-------|---------------|--------|
| TRACE | ~10,000+ | ~500+ |
| DEBUG | ~5,000 | ~250 |
| INFO | ~1,000 | ~50 |
| WARN | ~100 | ~5 |
| ERR | ~10 | ~0.5 |

## Best Practices

### DO

- Use appropriate levels from the start
- Include relevant context in messages
- Use consistent tags
- Investigate all ERR messages
- Review WARN messages periodically

### DON'T

- Don't use TRACE/DEBUG in production
- Don't log sensitive data (passwords, keys)
- Don't log packet payloads (performance)
- Don't use string concatenation in hot paths
- Don't forget to strip debug logs in release

## Performance Impact

- Logging has measurable overhead
- `LOG_*` macros short-circuit (check level before formatting)
- File/syslog I/O is blocking
- Consider async logging for high-throughput scenarios
