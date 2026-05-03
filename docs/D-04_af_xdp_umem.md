# D-04: AF_XDP UMEM Architecture

This document describes the AF_XDP UMEM architecture and the relationship between fill/completion rings.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Network Interface Card (NIC)                  │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ DMA (Direct Memory Access)
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     UMEM (Userspace Memory Region)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐              │
│  │  Frame 0 │ │  Frame 1 │ │  Frame 2 │ │  Frame N │  ...         │
│  │  4096 B  │ │  4096 B  │ │  4096 B  │ │  4096 B  │              │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘              │
│                                                                      │
│  [----------------- UMEM Area (mmap'd) -----------------]         │
│  Size = num_frames * frame_size                                       │
└─────────────────────────────────────────────────────────────────────┘
         │                       ▲                       ▲
         │                       │                       │
         │ Read                  │ Write                 │
         ▼                       │                       │
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│    Fill Ring     │    │ Completion Ring  │    │    RX/TX Ring    │
│                  │    │                  │    │   (in kernel)    │
│ Producer: Kernel │    │ Producer: Kernel │    │                  │
│ Consumer: User   │    │ Consumer: User   │    │                  │
└──────────────────┘    └──────────────────┘    └──────────────────┘
         │                       ▲                       ▲
         │                       │                       │
         │     Ownership          │     Ownership          │
         │     Transfer          │     Transfer           │
         └───────────────────────┴───────────────────────┘
                    ▲                       │
                    │                       ▼
         ┌──────────────────┐    ┌──────────────────┐
         │   AF_XDP Socket  │◄──►│   User Space     │
         │   (Kernel)       │    │   Application    │
         └──────────────────┘    └──────────────────┘
```

## UMEM (Userspace Memory)

### What is UMEM?

UMEM is a contiguous memory region registered with the kernel for zero-copy packet I/O. It is divided into equally-sized **frames**.

### Configuration

```c
struct xdp_umem_reg mr = {
    .addr = 0,           // Let kernel choose address (or specify)
    .len = num_frames * frame_size,  // Total UMEM size
    .chunk_size = frame_size,        // Size of each frame (must be power of 2)
    .headroom = 0,        // Optional headroom before packet data
    .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG,  // Allow any alignment
};
```

### Frame Layout

```
Frame 0: [addr + 0 * frame_size]
Frame 1: [addr + 1 * frame_size]
Frame 2: [addr + 2 * frame_size]
...
Frame N: [addr + N * frame_size]
```

Each frame can hold one packet. Frame size typically matches MTU (1500 bytes) plus headroom.

## Fill Ring

### Purpose
Transfers **empty frames** from user space to the kernel for receiving packets.

### Operation

1. **User Space** fills the ring with frame addresses
2. **Kernel** consumes frame addresses and DMA-receives packets into them
3. **Kernel** moves filled frames to the completion ring

### Ring Layout

```c
struct xdp_desc {
    __u64 addr;    // Frame address in UMEM
    __u32 len;     // Frame length
    __u32 options; // Options (typically 0)
};
```

### Indices

```c
volatile __u64 *fprod = /* producer index (kernel writes) */;
volatile __u64 *fcons = /* consumer index (user writes) */;
```

### Data Flow: Fill Ring

```
Initial State:
  Fill Ring: [addr0, addr1, addr2, ..., addrN]  (all pre-filled)
  fprod = N, fcons = 0

After Kernel Receives Packet:
  Fill Ring: [XXXX, addr1, addr2, ..., addrN]  (addr0 consumed)
  fprod unchanged, fcons = 1

User Refills:
  Fill Ring: [addr0', addr1, addr2, ..., addrN]  (user adds new frame)
  fcons incremented
```

## Completion Ring

### Purpose
Returns **filled frames** from kernel to user space after packet reception.

### Operation

1. **Kernel** DMA-receives packet into frame
2. **Kernel** moves frame address to completion ring
3. **User Space** consumes frame, processes packet
4. **User Space** returns frame address to fill ring

### Data Flow: Completion Ring

```
After Kernel Receives Packet:
  Completion Ring: [addr0_filled, XXXX, XXXX, ...]
  cprod incremented

User Processes and Returns Frame:
  Frame processed by user-space DPI
  Frame returned to fill ring
  ccons incremented
```

## Complete Packet Flow

### Step-by-Step

1. **Initialization**:
   ```
   User: Pre-fills fill ring with all frame addresses
   Kernel: Sees N available frames
   ```

2. **Packet Reception**:
   ```
   NIC DMA -> Frame in UMEM
   Kernel: Takes frame from fill ring, receives packet
   Kernel: Puts frame address in completion ring
   ```

3. **User Processing**:
   ```
   User: Sees frame in completion ring
   User: Reads packet data from frame
   User: Performs DPI (BMH pattern matching, TLS parsing)
   ```

4. **Frame Recycling**:
   ```
   User: Returns frame address to fill ring
   User: Updates fcons (consumer index)
   Kernel: Sees available frame for next reception
   ```

## Code Implementation

### Socket Setup (from af_xdp.cpp)

```cpp
// Create AF_XDP socket
sock_fd_ = socket(AF_XDP, SOCK_RAW, 0);

// Register UMEM
setsockopt(sock_fd_, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));

// Bind to interface and queue
struct sockaddr_xdp addr = {};
addr.sxdp_ifindex = ifindex;
addr.sxdp_queue_id = queue_id;
bind(sock_fd_, (struct sockaddr*)&addr, sizeof(addr));

// Get ring offsets
struct xdp_mmap_offsets off = {};
getsockopt(sock_fd_, SOL_XDP, XDP_MMAP_OFFSETS, &off, optlen);

// mmap fill and completion rings
fill_ring_ = mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
                  PROT_READ | PROTWRITE, MAP_SHARED,
                  sock_fd_, XDP_UMEM_PGOFF_FILL_RING);

completion_ring_ = mmap(nullptr, num_frames_ * sizeof(struct xdp_desc),
                        PROT_READ | PROT_WRITE, MAP_SHARED,
                        sock_fd_, XDP_UMEM_PGOFF_COMPLETION_RING);
```

### Receive Loop

```cpp
while (running_) {
    // 1. Process completion ring - recycle frames
    while (*ccons != *cprod) {
        uint32_t idx = (*ccons) & (num_frames_ - 1);
        uint64_t frame_addr = completion_ring_[idx].addr;

        // Return to fill ring
        fill_ring_[(*fprod) & (num_frames_ - 1)].addr = frame_addr;
        (*fprod)++;
        (*ccons)++;
    }

    // 2. Receive packets
    int n = recvmmsg(sock_fd_, msg, batch_size, MSG_DONTWAIT, nullptr);

    // 3. Process received packets
    for (int i = 0; i < n; i++) {
        // BMH pattern matching
        // TLS metadata extraction
        // Return frame to completion ring
        completion_ring_[(*cprod) & (num_frames_ - 1)].addr = frame_addr;
        (*cprod)++;
    }
}
```

## Advantages of UMEM Architecture

| Feature | Benefit |
|---------|---------|
| Zero-copy | Data never copied between kernel and user space |
| Single DMA | Packet data written once by NIC, read by application |
| Lock-free rings | Producer/consumer indices enable lockless communication |
| Scalability | Multiple sockets can share UMEM (XDP_UMEM_SGND_FLAG) |

## Memory Requirements

```
num_frames = 4096
frame_size = 4096 (4KB)
UMEM size  = 4096 * 4096 = 16 MB

Per-frame metadata (implicit):
  - Fill ring entry: 16 bytes
  - Completion ring entry: 16 bytes
```

## Common Issues

### Frame Alignment
```c
// XDP_UMEM_UNALIGNED_CHUNK_FLAG allows non-power-of-2 frame sizes
mr.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG;
```

### Index Wrapping
```c
// Always use mask for power-of-2 ring sizes
uint32_t idx = (*ccons) & (num_frames_ - 1);
```

### Producer/Consumer Sync
```c
// Check available slots before producing
if ((*fprod - *fcons) < num_frames_) {
    // Safe to produce
}
```
