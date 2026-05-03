# D-03: eBPF Verifier Limitations

This document describes programming patterns that avoid eBPF verifier rejections.

## Verifier Overview

The eBPF verifier statically analyzes all possible execution paths before loading programs into the kernel. It ensures:
- No memory accesses out of bounds
- No null pointer dereferences
- No uninitialized variable usage
- All loops are bounded and will terminate
- Stack usage does not exceed 512 bytes

## Common Rejection Patterns

### 1. Unbounded Loops

**Bad Pattern**:
```c
for (__u32 i = 0; i < MAX_RULES; i++) {
    struct rule_entry *rule = bpf_map_lookup_elem(&rules, &i);
    if (!rule) break;
    // process rule
}
```

**Why Rejected**: The verifier cannot prove `MAX_RULES` is small enough.

**Good Pattern** - Bounded loop with compile-time constant:
```c
#define MAX_RULES_TO_CHECK 256

for (__u32 i = 0; i < MAX_RULES_TO_CHECK; i++) {
    __u32 key = i;
    struct rule_entry *rule = bpf_map_lookup_elem(&rules, &key);
    if (!rule) break;
    // process rule
}
```

**Alternative** - Use `bpf_loop()` helper (kernel 5.13+):
```c
bpf_loop(256, lambda_callback, &ctx, 0);
```

### 2. Unbounded Map Iteration

**Bad Pattern**:
```c
struct bpf_spin_lock lock;
for (struct rule_entry *rule = 0; rule; rule++) { ... }
```

**Why Rejected**: No way for verifier to know iteration terminates.

**Good Pattern** - Index-based with bounded maximum:
```c
for (int i = 0; i < 256; i++) {
    __u32 key = i;
    struct rule_entry *rule = bpf_map_lookup_elem(&rules, &key);
    if (!rule) break;
    // process rule
}
```

### 3. Unchecked Pointer Arithmetic

**Bad Pattern**:
```c
void *ptr = data + offset;
__u8 val = *((__u8 *)ptr);  // May be out of bounds!
```

**Good Pattern** - Always validate against data_end:
```c
void *ptr = data + offset;
if (ptr + 1 > data_end) return XDP_DROP;
__u8 val = *((__u8 *)ptr);
```

### 4. Missing Boundary Checks

**Bad Pattern**:
```c
struct ethhdr *eth = data;
struct iphdr *ip = data + sizeof(*eth);
__u16 proto = bpf_ntohs(ip->protocol);  // No bounds check!
```

**Good Pattern**:
```c
struct ethhdr *eth = data;
if ((void *)(eth + 1) > data_end) return XDP_DROP;

struct iphdr *ip = data + sizeof(*eth);
if ((void *)(ip + 1) > data_end) return XDP_DROP;
```

## Safe Programming Patterns

### Always Use Pointer Validation

```c
static __always_inline int parse_tcp(struct iphdr *ip, void *data_end,
                                      __u16 *src_port, __u16 *dst_port) {
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return -1;

    *src_port = bpf_ntohs(tcp->source);
    *dst_port = bpf_ntohs(tcp->dest);
    return 0;
}
```

### Use __builtin_memset for Zero-Initialization

```c
struct flow_key key;
__builtin_memset(&key, 0, sizeof(key));
```

Instead of designated initializers (which may not be constant in older kernels).

### Prefer Stack Over Heap in Loops

**Bad** - Multiple alloca() calls in loop:
```c
for (int i = 0; i < n; i++) {
    void *ptr = bpf_alloca();
    // ...
}
```

**Good** - Single stack allocation:
```c
struct context ctx;
for (int i = 0; i < n; i++) {
    __builtin_memset(&ctx, 0, sizeof(ctx));
    // ...
}
```

### Avoid Function Pointer Indirection

The verifier tracks function call depth. Deep call chains may be rejected.

**Good Pattern** - Flat call structure:
```c
static __always_inline int handle_packet(struct xdp_md *ctx) {
    // All processing inline
    return XDP_PASS;
}
```

### Avoid Dynamic Stack Allocation Size

**Bad**:
```c
void process(void *data, __u32 len) {
    char buf[len];  // Variable length stack allocation
}
```

**Good**:
```c
#define MAX_BUF_SIZE 256
void process(void *data, __u32 len) {
    char buf[MAX_BUF_SIZE];
    __builtin_memcpy(buf, data, len < MAX_BUF_SIZE ? len : MAX_BUF_SIZE);
}
```

## Stack Usage Limits

- Maximum stack size: **512 bytes**
- Each `struct flow_key` = 16 bytes
- Each `struct alert_event` = 40 bytes
- Avoid large local arrays in packet processing path

## Helper Function Restrictions

### Allowed Helpers (XDP Context)

| Helper | Purpose |
|--------|---------|
| `bpf_map_lookup_elem` | Read from BPF map |
| `bpf_map_update_elem` | Write to BPF map |
| `bpf_map_delete_elem` | Delete from BPF map |
| `bpf_ringbuf_reserve` | Reserve ringbuf slot |
| `bpf_ringbuf_submit` | Submit ringbuf event |
| `bpf_ktime_get_ns` | Get current time |
| `bpf_ntohs` / `bpf_ntohl` | Byte order conversion |
| `bpf_per_cpu_ptr` | Per-CPU pointer access |

### Forbidden in XDP

- `bpf_probe_read_kernel` (use direct access)
- `bpf_probe_read_user` (use direct access)
- Any socket-related helpers (not available at XDP layer)

## Debugging Verifier Rejections

### Enable Verifier Logs

```bash
# View verifier output
clang -O2 -target bpf -g -c nids_bpf.c
ip link set dev eth0 xdp obj nids_bpf.o sec xdp 2>&1 | head -100
```

### Common Error Messages

| Error | Cause | Fix |
|-------|-------|-----|
| "invalid stack type" | Uninitialized variable | Use `__builtin_memset` |
| "unbounded loop" | Loop without constant bound | Add `#define MAX_ITERS 256` |
| "pointer arithmetic overflow" | Missing bounds check | Add `if (ptr > data_end)` |
| "loop must be bounded" | While/for loop | Use bounded for loop |
| "too many instructions" | Complex function | Split into helper functions |

## Best Practices Summary

1. Always validate pointers against `data_end`
2. Use `__always_inline` for packet processing functions
3. Prefer bounded `for` loops with constant limits
4. Zero-initialize structures with `__builtin_memset`
5. Keep stack usage under 512 bytes
6. Use `bpf_printk` for debugging (creates tracepoints)
7. Test with `ip link set dev eth0 xdp obj nids_bpf.o` to see verifier errors
