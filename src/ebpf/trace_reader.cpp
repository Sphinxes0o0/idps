/* SPDX-License-Identifier: MIT */
/*
 * trace_reader.cpp - Tracepoint 事件读取器实现
 *
 * 从 tracepoint BPF 程序的 ringbuf 读取进程事件
 */

#include "trace_reader.h"
#include "core/logger.h"
#include <unistd.h>
#include <cstring>
#include <errno.h>

namespace nids {

TraceReader::TraceReader()
    : obj_(nullptr)
    , rb_(nullptr)
    , ringbuf_fd_(-1) {
}

TraceReader::~TraceReader() {
    stop();
}

bool TraceReader::init(const char* bpf_object_path) {
    if (!bpf_object_path) {
        LOG_ERR("trace", "null bpf object path");
        return false;
    }

    struct bpf_object_open_opts opts = {};
    opts.sz = sizeof(opts);
    opts.object_name = "nids_trace";

    obj_ = bpf_object__open_file(bpf_object_path, &opts);
    if (libbpf_get_error(obj_)) {
        char err_buf[256];
        libbpf_strerror(libbpf_get_error(obj_), err_buf, sizeof(err_buf));
        LOG_ERR("trace", "failed to open BPF object: %s", err_buf);
        obj_ = nullptr;
        return false;
    }

    int err = bpf_object__load(obj_);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));
        LOG_ERR("trace", "failed to load BPF object: %s", err_buf);
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    struct bpf_map* map = bpf_object__find_map_by_name(obj_, "process_events");
    if (!map) {
        LOG_ERR("trace", "failed to find 'process_events' map");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    ringbuf_fd_ = bpf_map__fd(map);
    if (ringbuf_fd_ < 0) {
        LOG_ERR("trace", "failed to get ringbuf fd");
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }

    LOG_INFO("trace", "initialized with ringbuf fd %d", ringbuf_fd_);
    return true;
}

void TraceReader::set_process_callback(ProcessCallback cb) {
    callback_ = std::move(cb);
}

void TraceReader::start_poll(int timeout_ms) {
    if (running_.load()) {
        LOG_WARN("trace", "already running");
        return;
    }

    if (ringbuf_fd_ < 0) {
        LOG_ERR("trace", "ringbuf not initialized");
        return;
    }

    rb_ = ring_buffer__new(ringbuf_fd_, process_event_callback, this, nullptr);
    if (!rb_) {
        LOG_ERR("trace", "failed to create ring buffer");
        return;
    }

    running_ = true;
    LOG_INFO("trace", "started polling on ringbuf fd %d", ringbuf_fd_);

    while (running_.load()) {
        int err = ring_buffer__poll(rb_, timeout_ms);
        if (err < 0 && err != -EINTR) {
            if (running_.load()) {
                LOG_ERR("trace", "ring_buffer__poll error: %s", strerror(-err));
            }
            break;
        }
    }

    running_ = false;
    LOG_INFO("trace", "stopped polling");
}

void TraceReader::stop() {
    if (!running_.load()) {
        return;
    }

    running_ = false;

    if (rb_) {
        ring_buffer__free(rb_);
        rb_ = nullptr;
    }

    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }

    ringbuf_fd_ = -1;
}

int TraceReader::process_event_callback(void* ctx, void* data, size_t len) {
    auto* reader = static_cast<TraceReader*>(ctx);

    constexpr size_t expected_size = offsetof(ProcessEvent, type);
    if (len < expected_size) {
        LOG_WARN("trace", "event too small: %zu (expected %zu)", len, expected_size);
        return 1;
    }

    auto* event = static_cast<ProcessEvent*>(data);
    reader->processed_count_++;

    if (reader->callback_) {
        try {
            reader->callback_(*event);
        } catch (const std::exception& e) {
            LOG_ERR("trace", "callback exception: %s", e.what());
        }
    }

    return 0;
}

} // namespace nids
