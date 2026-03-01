#pragma once
#include <atomic>
#include <cstdio>
#include <ctime>
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

// ---- Global log level (change at runtime) -----------------------------------
extern std::atomic<LogLevel> g_log_level;

// Set level by name string (trace/debug/info/warn/error/off)
void log_set_level(const std::string& name);

// Initialise the logging subsystem (call once at startup).
// ident: program identity used by syslog and as the spdlog logger name.
void log_init(const std::string& ident = "nids");

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
