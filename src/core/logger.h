#pragma once
#include <atomic>
#include <cstdio>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>

namespace nids {

enum class LogLevel : int {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERR   = 4,   // avoid clash with errno macro ERROR
    OFF   = 5
};

// ---- Pluggable sink interface ------------------------------------------------
// Implement this to redirect log output to spdlog, syslog, Android log, etc.
struct LogSink {
    virtual ~LogSink() = default;
    // Called for every log message that passes the level filter.
    // lv  : severity level
    // tag : module tag string
    // msg : fully-formatted message (no trailing newline)
    virtual void write(LogLevel lv, const char* tag, const char* msg) = 0;
};

// Replace the active sink (pass nullptr to restore the built-in stderr sink).
// Thread-safe: subsequent log_write() calls will use the new sink.
void log_set_sink(std::shared_ptr<LogSink> sink);

// ---- Global log level (change at runtime) -----------------------------------
extern std::atomic<LogLevel> g_log_level;

// Set level by name string (trace/debug/info/warn/error/off)
void log_set_level(const std::string& name);

// ---- Internal write (thread-safe) -------------------------------------------
void log_write(LogLevel lv, const char* tag, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

// ---- Convenience macros with short-circuit check ----------------------------
#define LOG_TRACE(tag, ...) \
    do { if (nids::g_log_level.load(std::memory_order_relaxed) <= nids::LogLevel::TRACE) \
             nids::log_write(nids::LogLevel::TRACE, tag, __VA_ARGS__); } while(0)

#define LOG_DEBUG(tag, ...) \
    do { if (nids::g_log_level.load(std::memory_order_relaxed) <= nids::LogLevel::DEBUG) \
             nids::log_write(nids::LogLevel::DEBUG, tag, __VA_ARGS__); } while(0)

#define LOG_INFO(tag, ...) \
    do { if (nids::g_log_level.load(std::memory_order_relaxed) <= nids::LogLevel::INFO) \
             nids::log_write(nids::LogLevel::INFO,  tag, __VA_ARGS__); } while(0)

#define LOG_WARN(tag, ...) \
    do { if (nids::g_log_level.load(std::memory_order_relaxed) <= nids::LogLevel::WARN) \
             nids::log_write(nids::LogLevel::WARN,  tag, __VA_ARGS__); } while(0)

#define LOG_ERR(tag, ...) \
    do { if (nids::g_log_level.load(std::memory_order_relaxed) <= nids::LogLevel::ERR) \
             nids::log_write(nids::LogLevel::ERR,   tag, __VA_ARGS__); } while(0)

} // namespace nids
