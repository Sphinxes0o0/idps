# D-06: XDP Return Code Reference

This document describes the XDP (eXpress Data Path) return codes used by the IDPS kernel eBPF program.

## XDP Actions

| Return Code | Value | Description |
|-------------|-------|-------------|
| `XDP_ABORTED` | 0 | Packet dropped due to exception (traced) |
| `XDP_DROP` | 1 | Packet silently dropped by XDP |
| `XDP_PASS` | 2 | Packet passed to kernel network stack |
| `XDP_TX` | 3 | Packet transmitted out same interface |
| `XDP_REDIRECT` | 4 | Packet redirected via redirect map |

## IDPS Return Code Usage

### XDP_PASS

Packets are allowed to continue to the kernel network stack after processing.

**Used when:**
- Packet is not malicious
- Fragment reassembly is in progress (waiting for more fragments)
- Flow tracking is updated
- Rule matched but only logging (not dropping)

```c
return XDP_PASS;  // Allow packet to continue
```

### XDP_DROP

Packets are silently discarded at the XDP layer, before reaching the kernel network stack.

**Used when:**
- DDoS attack detected (SYN flood, ICMP flood, etc.)
- Malicious fragment pattern detected
- Rate limit exceeded
- Explicit drop rule matched

```c
return XDP_DROP;  // Silently discard packet
```

### XDP_ABORTED

Packet dropped due to an exception. These are traced for debugging.

**Used when:**
- Parse error in critical path
- Map lookup failed unexpectedly
- Internal error during processing

```c
return XDP_ABORTED;  // Drop with tracing
```

## Return Code Flow in IDPS

```
Packet arrives at XDP hook
         |
         v
+------------------+
| Parse 5-tuple    |
+------------------+
         |
         v
+------------------+
| Defrag check     |---- Fragment ----> XDP_PASS (wait for more)
+------------------+
         |
         v
+------------------+
| DDoS detection   |---- Attack -----> XDP_DROP
+------------------+
         |
         v
+------------------+
| Rule matching    |---- Match ------> XDP_PASS (log event)
+------------------+
         |
         v
+------------------+
| Normal packet    |----------------> XDP_PASS
+------------------+
```

## Impact on Performance

| Return Code | Performance Impact |
|-------------|-------------------|
| `XDP_PASS` | Minimal overhead - packet continues normally |
| `XDP_DROP` | Best performance - packet discarded early |
| `XDP_ABORTED` | Similar to DROP but with tracing overhead |

## sysstat Counter Mapping

The IDPS tracks statistics via the `stats` PERCPU_ARRAY map:

| Stats Index | Counter Name | Triggered By |
|-------------|--------------|--------------|
| `STATS_PACKETS_PASSED` | Packets passed to stack | `XDP_PASS` |
| `STATS_PACKETS_DROPPED` | Packets dropped | `XDP_DROP` |

## Return Code and Ringbuf Events

- `XDP_PASS` with event: Sends event via ringbuf (e.g., `RULE_MATCH`, `NEW_FLOW`)
- `XDP_DROP` with event: Sends alert event (e.g., `DDoS_ALERT`, `SYN_FLOOD`)

Events are sent BEFORE the return code to ensure alerts are not lost.

## Notes

- XDP runs at very high privilege (NIC driver level)
- Return codes are processed in the NIC driver's XDP hook
- `XDP_TX` and `XDP_REDIRECT` are not currently used by IDPS
