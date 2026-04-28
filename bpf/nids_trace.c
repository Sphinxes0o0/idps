/* SPDX-License-Identifier: MIT */
/*
 * nids_trace.c - eBPF Tracepoint 程序
 *
 * 用于进程监控的 tracepoint 程序，跟踪:
 * - sys_enter_connect: 跟踪 outgoing 连接
 * - sys_enter_accept: 跟踪 incoming 连接
 * - sys_enter_close: 跟踪文件描述符关闭
 * - sched_process_exit: 跟踪进程退出
 * - sched_process_fork: 跟踪进程 fork
 * - sched_stat_run: 跟踪 CPU 时间使用
 */

#include "nids_common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>

#define TASK_COMM_LEN 16

enum proc_event_type {
    PROC_EVENT_CONNECT = 0,
    PROC_EVENT_ACCEPT = 1,
    PROC_EVENT_CLOSE = 2,
    PROC_EVENT_EXIT = 3,
    PROC_EVENT_FORK = 4,
    PROC_EVENT_EXEC = 5,
};

struct proc_trace_event {
    __u8 event_type;
    __u8 padding1[3];
    __u8 padding2[4];
    pid_t pid;
    pid_t tid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    int fd;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 exit_code;
    __u64 timestamp;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} process_events SEC(".maps");

static __always_inline void send_proc_trace_event(struct proc_trace_event *event) {
    bpf_ringbuf_output(&process_events, event, sizeof(*event), 0);
}

/*
 * Send process event via shared events ringbuf
 * Uses process_event from nids_common.h
 */
static __always_inline int send_process_event_ringbuf(__u32 pid, __u32 tid, __u32 uid,
                                                     __u32 fd, __u8 event_type,
                                                     __u8 addr_family, __u8 protocol,
                                                     __u32 src_ip, __u32 dst_ip,
                                                     __u16 src_port, __u16 dst_port) {
    struct process_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return -1;
    }

    event->timestamp = bpf_ktime_get_ns();
    event->pid = pid;
    event->tid = tid;
    event->uid = uid;
    event->fd = fd;
    event->event_type = event_type;
    event->addr_family = addr_family;
    event->protocol = protocol;
    event->src_ip = src_ip;
    event->dst_ip = dst_ip;
    event->src_port = src_port;
    event->dst_port = dst_port;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_sys_enter_connect(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid, tid, uid;
    __u32 fd;
    void *sockaddr_ptr;
    __u8 addr_family = 0;
    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 protocol = 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)(pid_tgid >> 32);
    tid = (__u32)(pid_tgid & 0xFFFFFFFF);

    __u32 uid_gid = bpf_get_current_uid_gid();
    uid = uid_gid >> 32;

    fd = (__u32)ctx->args[0];
    sockaddr_ptr = (void *)ctx->args[1];

    if (sockaddr_ptr) {
        __u16 family;
        if (bpf_probe_read_kernel(&family, sizeof(family), sockaddr_ptr) == 0) {
            addr_family = (__u8)family;

            if (family == AF_INET) {
                struct {
                    __u16 sin_family;
                    __u16 sin_port;
                    __u32 sin_addr;
                } sin;
                if (bpf_probe_read_kernel(&sin, sizeof(sin), sockaddr_ptr) == 0) {
                    src_ip = sin.sin_addr;
                    src_port = sin.sin_port;
                    dst_ip = sin.sin_addr;
                    dst_port = sin.sin_port;
                    protocol = IPPROTO_TCP;
                }
            } else if (family == AF_INET6) {
                struct {
                    __u16 sin6_family;
                    __u16 sin6_port;
                    __u32 sin6_flowinfo;
                    __u8 sin6_addr[16];
                    __u32 sin6_scope_id;
                } sin6;
                if (bpf_probe_read_kernel(&sin6, sizeof(sin6), sockaddr_ptr) == 0) {
                    src_ip = *((__u32 *)sin6.sin6_addr);
                    src_port = sin6.sin6_port;
                    dst_ip = *((__u32 *)sin6.sin6_addr);
                    dst_port = sin6.sin6_port;
                    protocol = IPPROTO_TCP;
                }
            }
        }
    }

    send_process_event_ringbuf(pid, tid, uid, fd, EVENT_PROCESS_CONNECT,
                              addr_family, protocol, src_ip, dst_ip, src_port, dst_port);

    return 0;
}

struct accept_event {
    pid_t pid;
    pid_t tid;
    uid_t uid;
    char comm[TASK_COMM_LEN];
    int listen_fd;
    int new_fd;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 padding[3];
    __u64 timestamp;
};

static __always_inline void send_accept_event(struct accept_event *event) {
    bpf_ringbuf_output(&process_events, event, sizeof(*event), 0);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} accept_pending SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_accept")
int tracepoint_sys_enter_accept(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u64 key = (__u64)tid << 32 | (__u64)ctx->args[0];
    __u64 val = bpf_ktime_get_ns();

    bpf_map_update_elem(&accept_pending, &key, &val, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint_sys_exit_accept(struct trace_event_raw_sys_exit *ctx)
{
    struct accept_event event = {};

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    int ret = ctx->ret;
    if (ret < 0) {
        return 0;
    }

    event.new_fd = ret;
    event.listen_fd = ctx->args[0];
    event.protocol = IPPROTO_TCP;
    event.timestamp = bpf_ktime_get_ns();

    __u64 key = (__u64)event.tid << 32 | (__u64)event.listen_fd;
    bpf_map_delete_elem(&accept_pending, &key);

    send_accept_event(&event);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint_sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid, tid, uid;
    __u32 fd;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid = (__u32)(pid_tgid >> 32);
    tid = (__u32)(pid_tgid & 0xFFFFFFFF);

    __u32 uid_gid = bpf_get_current_uid_gid();
    uid = uid_gid >> 32;

    fd = (__u32)ctx->args[0];

    send_process_event_ringbuf(pid, tid, uid, fd, EVENT_PROCESS_CLOSE,
                              0, 0, 0, 0, 0, 0);

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct proc_trace_event event = {};

    event.event_type = PROC_EVENT_EXIT;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.tid = (__u32)bpf_get_current_pid_tgid();
    event.uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.exit_code = ctx->exit_code;

    event.timestamp = bpf_ktime_get_ns();

    send_proc_trace_event(&event);
    return 0;
}

/*
 * Memory tracking structures
 */

struct mem_track {
    __u64 total_alloc;
    __u64 total_free;
    __u64 current_rss;
    __u64 alloc_count;
    __u64 free_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct mem_track);
} mem_monitor SEC(".maps");

static __always_inline void update_mem_track(__u32 pid, __u64 bytes, bool alloc)
{
    struct mem_track *track;
    struct mem_track zero = {};

    track = bpf_map_lookup_elem(&mem_monitor, &pid);
    if (!track) {
        bpf_map_update_elem(&mem_monitor, &pid, &zero, BPF_ANY);
        track = bpf_map_lookup_elem(&mem_monitor, &pid);
        if (!track)
            return;
    }

    if (alloc) {
        track->total_alloc += bytes;
        track->alloc_count += 1;
        track->current_rss += bytes;
    } else {
        track->total_free += bytes;
        track->free_count += 1;
        if (track->current_rss >= bytes)
            track->current_rss -= bytes;
        else
            track->current_rss = 0;
    }
}

SEC("tracepoint/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 bytes = ctx->bytes_alloc;

    update_mem_track(pid, bytes, true);
    return 0;
}

SEC("tracepoint/mm/mm_page_alloc")
int handle_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 bytes = ctx->page_size;

    update_mem_track(pid, bytes, true);
    return 0;
}

/*
 * CPU tracking via sched tracepoints
 */

struct cpu_track {
    __u64 total_cpu_ns;
    __u64 last_update;
    __u64 run_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct cpu_track);
} cpu_monitor SEC(".maps");

static __always_inline void update_cpu_track(__u32 pid, __u64 cpu_ns)
{
    struct cpu_track *track;
    struct cpu_track zero = {};

    track = bpf_map_lookup_elem(&cpu_monitor, &pid);
    if (!track) {
        bpf_map_update_elem(&cpu_monitor, &pid, &zero, BPF_ANY);
        track = bpf_map_lookup_elem(&cpu_monitor, &pid);
        if (!track)
            return;
    }

    track->total_cpu_ns += cpu_ns;
    track->run_count += 1;
    track->last_update = bpf_ktime_get_ns();
}

SEC("tracepoint/sched/sched_process_fork")
int handle_sched_process_fork(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct cpu_track *track;
    struct cpu_track zero = {};

    track = bpf_map_lookup_elem(&cpu_monitor, &pid);
    if (!track) {
        bpf_map_update_elem(&cpu_monitor, &pid, &zero, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/sched/sched_stat_run")
int handle_sched_stat_run(struct trace_event_raw_sched_stat_run *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 cpu_ns = ctx->runtime;

    update_cpu_track(pid, cpu_ns);
    return 0;
}

static __always_inline void update_fd_count(__u32 pid, __u8 type, int increment)
{
    __u32 key = pid;
    struct fd_track *track = bpf_map_lookup_elem(&fd_monitor, &key);
    if (!track) {
        struct fd_track new_track = {};
        new_track.total_fds = 0;
        new_track.socket_count = 0;
        new_track.file_count = 0;
        new_track.pipe_count = 0;
        new_track.timestamp = bpf_ktime_get_ns();
        bpf_map_update_elem(&fd_monitor, &key, &new_track, BPF_ANY);
        track = bpf_map_lookup_elem(&fd_monitor, &key);
        if (!track) return;
    }

    if (increment) {
        __sync_fetch_and_add(&track->total_fds, 1);
        track->timestamp = bpf_ktime_get_ns();
        switch (type) {
        case FD_TYPE_SOCKET:
            __sync_fetch_and_add(&track->socket_count, 1);
            break;
        case FD_TYPE_FILE:
            __sync_fetch_and_add(&track->file_count, 1);
            break;
        case FD_TYPE_PIPE:
            __sync_fetch_and_add(&track->pipe_count, 1);
            break;
        }
    } else {
        __sync_fetch_and_add(&track->total_fds, -1);
        track->timestamp = bpf_ktime_get_ns();
        switch (type) {
        case FD_TYPE_SOCKET:
            __sync_fetch_and_add(&track->socket_count, -1);
            break;
        case FD_TYPE_FILE:
            __sync_fetch_and_add(&track->file_count, -1);
            break;
        case FD_TYPE_PIPE:
            __sync_fetch_and_add(&track->pipe_count, -1);
            break;
        }
    }
}

static __always_inline void track_fd_type(__u32 pid, __u32 fd, __u8 type)
{
    struct fd_type_key key = {.pid = pid, .fd = fd};
    struct fd_type_val val = {.type = type, .padding = {0}};
    bpf_map_update_elem(&fd_type_track, &key, &val, BPF_ANY);
}

static __always_inline __u8 get_fd_type(__u32 pid, __u32 fd)
{
    struct fd_type_key key = {.pid = pid, .fd = fd};
    struct fd_type_val *val = bpf_map_lookup_elem(&fd_type_track, &key);
    if (val) {
        return val->type;
    }
    return FD_TYPE_UNKNOWN;
}

static __always_inline void remove_fd_type(__u32 pid, __u32 fd)
{
    struct fd_type_key key = {.pid = pid, .fd = fd};
    bpf_map_delete_elem(&fd_type_track, &key);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = ctx->ret;
    if ((int)fd < 0) return 0;

    track_fd_type(pid, fd, FD_TYPE_FILE);
    update_fd_count(pid, FD_TYPE_FILE, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_enter_socket(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = ctx->ret;
    if ((int)fd < 0) return 0;

    int domain = ctx->args[0];
    int type = ctx->args[1];
    int protocol = ctx->args[2];

    (void)domain;
    (void)type;
    (void)protocol;

    track_fd_type(pid, fd, FD_TYPE_SOCKET);
    update_fd_count(pid, FD_TYPE_SOCKET, 1);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 fd = ctx->args[0];

    __u8 type = get_fd_type(pid, fd);
    if (type != FD_TYPE_UNKNOWN) {
        update_fd_count(pid, type, 0);
        remove_fd_type(pid, fd);
    }
    return 0;
}

/*
 * I/O tracking via syscall tracepoints
 */

struct io_track {
    __u64 read_bytes;
    __u64 write_bytes;
    __u64 read_count;
    __u64 write_count;
    __u64 read_syscalls;
    __u64 write_syscalls;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, struct io_track);
} io_monitor SEC(".maps");

static __always_inline void update_io_track(__u32 pid, __u64 bytes, bool is_read)
{
    struct io_track *track;
    struct io_track zero = {};

    track = bpf_map_lookup_elem(&io_monitor, &pid);
    if (!track) {
        bpf_map_update_elem(&io_monitor, &pid, &zero, BPF_ANY);
        track = bpf_map_lookup_elem(&io_monitor, &pid);
        if (!track)
            return;
    }

    if (is_read) {
        track->read_bytes += bytes;
        track->read_count += 1;
        track->read_syscalls += 1;
    } else {
        track->write_bytes += bytes;
        track->write_count += 1;
        track->write_syscalls += 1;
    }
}

SEC("tracepoint/syscalls/sys_enter_read")
int handle_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 count = ctx->args[2];

    update_io_track(pid, count, true);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 count = ctx->args[2];

    update_io_track(pid, count, false);
    return 0;
}

struct iovec {
    void *iov_base;
    __u64 iov_len;
};

SEC("tracepoint/syscalls/sys_enter_readv")
int handle_enter_readv(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct iovec *iov = (struct iovec *)ctx->args[1];
    int iovcnt = (int)ctx->args[2];
    __u64 total_bytes = 0;

    if (iovcnt <= 0 || !iov)
        return 0;

    if (iovcnt > 8)
        iovcnt = 8;

#pragma clang loop unroll(disable)
    for (int i = 0; i < 8; i++) {
        if (i >= iovcnt)
            break;
        struct iovec vec;
        bpf_probe_read(&vec, sizeof(vec), &iov[i]);
        total_bytes += vec.iov_len;
    }

    update_io_track(pid, total_bytes, true);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int handle_enter_writev(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct iovec *iov = (struct iovec *)ctx->args[1];
    int iovcnt = (int)ctx->args[2];
    __u64 total_bytes = 0;

    if (iovcnt <= 0 || !iov)
        return 0;

    if (iovcnt > 8)
        iovcnt = 8;

#pragma clang loop unroll(disable)
    for (int i = 0; i < 8; i++) {
        if (i >= iovcnt)
            break;
        struct iovec vec;
        bpf_probe_read(&vec, sizeof(vec), &iov[i]);
        total_bytes += vec.iov_len;
    }

    update_io_track(pid, total_bytes, false);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
