/* SPDX-License-Identifier: MIT */
/*
 * trace_reader.h - Tracepoint 事件读取器
 *
 * 从 tracepoint BPF 程序的 ringbuf 读取进程事件
 */

#pragma once
#include <functional>
#include <memory>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <bpf/libbpf.h>

struct bpf_object;

namespace nids {

enum class ProcessEventType : uint8_t {
    CONNECT = 0,
    ACCEPT = 1,
    CLOSE = 2,
    EXIT = 3,
};

struct ProcessEvent {
    pid_t pid;
    pid_t tid;
    uid_t uid;
    char comm[16];
    int fd;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 padding[7];
    __u64 timestamp;
    ProcessEventType type;
};

using ProcessCallback = std::function<void(const ProcessEvent&)>;

class TraceReader {
public:
    TraceReader();
    ~TraceReader();

    TraceReader(const TraceReader&) = delete;
    TraceReader& operator=(const TraceReader&) = delete;

    bool init(const char* bpf_object_path);
    void set_process_callback(ProcessCallback cb);
    void start_poll(int timeout_ms = -1);
    void stop();

    bool is_running() const { return running_.load(); }
    uint64_t processed_count() const { return processed_count_.load(); }

private:
    static int process_event_callback(void* ctx, void* data, size_t len);

    bpf_object* obj_;
    struct ring_buffer* rb_;
    int ringbuf_fd_;
    ProcessCallback callback_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> processed_count_{0};
};

} // namespace nids
