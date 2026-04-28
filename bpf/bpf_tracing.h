/* SPDX-License-Identifier: MIT */
/*
 * bpf_tracing.h - libbpf-bootstrap compatible tracepoint macros
 *
 * Provides convenient macros for tracepoint argument parsing,
 * simplifying code like:
 *   // Before: struct trace_event_raw_sys_enter *ctx = ...; int fd = ctx->args[0];
 *   // After:  int fd = (int)ctx->args[0];
 */

#pragma once

#include <linux/bpf.h>
#include <linux/ptrace.h>

#define TASK_COMM_LEN 16

struct trace_event_raw_sys_enter {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long args[6];
};

struct trace_event_raw_sys_exit {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    long ret;
};

struct trace_event_raw_sched_process_template {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int prio;
    int pid;
    unsigned short common_padding;
    unsigned short parent_pid;
    unsigned short real_parent_pid;
    unsigned short group_leader_pid;
    unsigned int sessionid;
    unsigned int major_fault;
    unsigned int minor_fault;
    unsigned int cmin_flt;
    unsigned int cmaj_flt;
    unsigned int cr_maj_flt;
    unsigned int cr_min_flt;
    unsigned int exit_code;
    unsigned int exit_signal;
};

struct trace_event_raw_sched_stat_run {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    unsigned long long runtime;
};

struct trace_event_raw_kmalloc {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    unsigned long caller;
    unsigned long call_site;
    const void *ptr;
    __u64 bytes_alloc;
    __u64 bytes_free;
    __u64 gfp_flags;
};

struct trace_event_raw_mm_page_alloc {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    unsigned long pfn;
    unsigned long order;
    unsigned long gfp_flags;
    unsigned long migratetype;
    unsigned long page_size;
};

#define BPF_TRACE_sys_enter(name, ...) \
SEC("tracepoint/syscalls/sys_enter_" #name) \
static __always_inline int __bpf_trace_##name(struct trace_event_raw_sys_enter *ctx)

#define BPF_TRACE_sys_exit(name, ...) \
SEC("tracepoint/syscalls/sys_exit_" #name) \
static __always_inline int __bpf_trace_##name(struct trace_event_raw_sys_exit *ctx)

#define BPF_TRACE_sched_process_exit() \
SEC("tracepoint/sched/sched_process_exit") \
static __always_inline int __bpf_trace_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)

#define BPF_TRACE_sched_process_fork() \
SEC("tracepoint/sched/sched_process_fork") \
static __always_inline int __bpf_trace_sched_process_fork(struct trace_event_raw_sched_process_template *ctx)

#define BPF_TRACE_sched_stat_run() \
SEC("tracepoint/sched/sched_stat_run") \
static __always_inline int __bpf_trace_sched_stat_run(struct trace_event_raw_sched_stat_run *ctx)

#define BPF_TRACE_kmem_kmalloc() \
SEC("tracepoint/kmem/kmalloc") \
static __always_inline int __bpf_trace_kmem_kmalloc(struct trace_event_raw_kmalloc *ctx)

#define BPF_TRACE_mm_page_alloc() \
SEC("tracepoint/mm/mm_page_alloc") \
static __always_inline int __bpf_trace_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)

#define PT_REGS_PARM1(x) ((x)->args[0])
#define PT_REGS_PARM2(x) ((x)->args[1])
#define PT_REGS_PARM3(x) ((x)->args[2])
#define PT_REGS_PARM4(x) ((x)->args[3])
#define PT_REGS_PARM5(x) ((x)->args[4])
#define PT_REGS_PARM6(x) ((x)->args[5])
#define PT_REGS_RET(x) ((x)->ret)
#define PT_REGS_PARM1_CORE(x) ((x)->args[0])
#define PT_REGS_PARM2_CORE(x) ((x)->args[1])
#define PT_REGS_PARM3_CORE(x) ((x)->args[2])
#define PT_REGS_PARM4_CORE(x) ((x)->args[3])
#define PT_REGS_PARM5_CORE(x) ((x)->args[4])
#define PT_REGS_PARM6_CORE(x) ((x)->args[5])
#define PT_REGS_RET_CORE(x) ((x)->ret)
