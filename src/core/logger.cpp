#include "logger.h"
#include <cstdarg>
#include <cstring>
#include <mutex>

namespace nids {

std::atomic<LogLevel> g_log_level{LogLevel::INFO};

// ---- Built-in stderr sink ---------------------------------------------------

namespace {

static const char* level_str(LogLevel lv) {
    switch (lv) {
        case LogLevel::TRACE: return "\033[90mTRACE\033[0m";
        case LogLevel::DEBUG: return "\033[36mDEBUG\033[0m";
        case LogLevel::INFO:  return "\033[32m INFO\033[0m";
        case LogLevel::WARN:  return "\033[33m WARN\033[0m";
        case LogLevel::ERR:   return "\033[31m  ERR\033[0m";
        default:              return "     ";
    }
}

// Timestamp as HH:MM:SS.mmm
static void timestamp(char* buf, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_info;
    localtime_r(&ts.tv_sec, &tm_info);
    int ms = static_cast<int>(ts.tv_nsec / 1'000'000);
    snprintf(buf, n, "%02d:%02d:%02d.%03d",
             tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ms);
}

struct StderrSink : public LogSink {
    void write(LogLevel lv, const char* tag, const char* msg) override {
        char ts[16];
        timestamp(ts, sizeof(ts));
        fprintf(stderr, "[%s][%s][%-10s] %s\n", level_str(lv), ts, tag, msg);
    }
};

} // anonymous namespace

// ---- Active sink (guarded by s_log_mutex) -----------------------------------

static std::mutex              s_log_mutex;
static std::shared_ptr<LogSink> s_sink = std::make_shared<StderrSink>();

void log_set_sink(std::shared_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lg(s_log_mutex);
    s_sink = sink ? std::move(sink) : std::make_shared<StderrSink>();
}

// ---- Public API -------------------------------------------------------------

void log_write(LogLevel lv, const char* tag, const char* fmt, ...) {
    char msg[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lg(s_log_mutex);
    s_sink->write(lv, tag, msg);
}

void log_set_level(const std::string& name) {
    if      (name == "trace") g_log_level.store(LogLevel::TRACE);
    else if (name == "debug") g_log_level.store(LogLevel::DEBUG);
    else if (name == "info")  g_log_level.store(LogLevel::INFO);
    else if (name == "warn")  g_log_level.store(LogLevel::WARN);
    else if (name == "error") g_log_level.store(LogLevel::ERR);
    else if (name == "off")   g_log_level.store(LogLevel::OFF);
}

} // namespace nids
