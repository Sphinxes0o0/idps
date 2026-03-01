#include "logger.h"
#include <cstdarg>
#include <cstdio>
#include <mutex>

// Platform-specific includes
#if defined(LOGGER_BACKEND_SYSLOG)
#  include <syslog.h>
#elif defined(LOGGER_BACKEND_ANDROID)
#  include <android/log.h>
#elif defined(LOGGER_BACKEND_NLOG)
#  include <spdlog/spdlog.h>
#  include <spdlog/sinks/stdout_color_sinks.h>
#  include <memory>
#else
#  include <ctime>
#endif

namespace nids {

std::atomic<LogLevel> g_log_level{LogLevel::INFO};

// Maximum formatted message buffer size (all backends).
static constexpr std::size_t LOG_MSG_BUF = 512;

// Common: convert a level name to LogLevel (returns current level if unknown).
static LogLevel level_from_name(const std::string& name) {
    if (name == "trace") return LogLevel::TRACE;
    if (name == "debug") return LogLevel::DEBUG;
    if (name == "info")  return LogLevel::INFO;
    if (name == "warn")  return LogLevel::WARN;
    if (name == "error") return LogLevel::ERR;
    if (name == "off")   return LogLevel::OFF;
    return g_log_level.load();
}

// ---- Syslog backend ---------------------------------------------------------
#if defined(LOGGER_BACKEND_SYSLOG)

static int to_syslog_priority(LogLevel lv) {
    switch (lv) {
        case LogLevel::TRACE: /* fall through */
        case LogLevel::DEBUG: return LOG_DEBUG;
        case LogLevel::INFO:  return LOG_INFO;
        case LogLevel::WARN:  return LOG_WARNING;
        case LogLevel::ERR:   return LOG_ERR;
        default:              return LOG_DEBUG;
    }
}

void log_init(const std::string& ident) {
    openlog(ident.c_str(), LOG_PID | LOG_CONS, LOG_DAEMON);
}

void log_write(LogLevel lv, const char* tag, const char* fmt, ...) {
    char msg[LOG_MSG_BUF];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    syslog(to_syslog_priority(lv), "[%s] %s", tag, msg);
}

void log_set_level(const std::string& name) {
    g_log_level.store(level_from_name(name));
}

// ---- Android liblog backend -------------------------------------------------
#elif defined(LOGGER_BACKEND_ANDROID)

static android_LogPriority to_android_priority(LogLevel lv) {
    switch (lv) {
        case LogLevel::TRACE: return ANDROID_LOG_VERBOSE;
        case LogLevel::DEBUG: return ANDROID_LOG_DEBUG;
        case LogLevel::INFO:  return ANDROID_LOG_INFO;
        case LogLevel::WARN:  return ANDROID_LOG_WARN;
        case LogLevel::ERR:   return ANDROID_LOG_ERROR;
        default:              return ANDROID_LOG_DEFAULT;
    }
}

void log_init(const std::string& /*ident*/) {
    // Android logcat uses the per-call tag; no global init needed.
}

void log_write(LogLevel lv, const char* tag, const char* fmt, ...) {
    char msg[LOG_MSG_BUF];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    __android_log_print(to_android_priority(lv), tag, "%s", msg);
}

void log_set_level(const std::string& name) {
    g_log_level.store(level_from_name(name));
}

// ---- nlog (spdlog) backend --------------------------------------------------
#elif defined(LOGGER_BACKEND_NLOG)

static spdlog::level::level_enum to_spdlog_level(LogLevel lv) {
    switch (lv) {
        case LogLevel::TRACE: return spdlog::level::trace;
        case LogLevel::DEBUG: return spdlog::level::debug;
        case LogLevel::INFO:  return spdlog::level::info;
        case LogLevel::WARN:  return spdlog::level::warn;
        case LogLevel::ERR:   return spdlog::level::err;
        default:              return spdlog::level::off;
    }
}

static std::shared_ptr<spdlog::logger> s_logger;
static std::mutex s_logger_mutex;
static std::string s_nlog_ident{"nids"};  // default ident used by lazy init

static spdlog::logger& get_logger() {
    std::lock_guard<std::mutex> lg(s_logger_mutex);
    if (!s_logger)
        s_logger = spdlog::stdout_color_mt(s_nlog_ident);
    return *s_logger;
}

void log_init(const std::string& ident) {
    std::lock_guard<std::mutex> lg(s_logger_mutex);
    s_nlog_ident = ident;
    // Reuse an already-registered logger or create a new one.
    auto existing = spdlog::get(ident);
    s_logger = existing ? existing : spdlog::stdout_color_mt(ident);
    s_logger->set_level(to_spdlog_level(g_log_level.load()));
    s_logger->set_pattern("[%H:%M:%S.%e][%^%l%$][%n] %v");
}

void log_write(LogLevel lv, const char* tag, const char* fmt, ...) {
    char msg[LOG_MSG_BUF];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    get_logger().log(to_spdlog_level(lv), "[{}] {}", tag, msg);
}

void log_set_level(const std::string& name) {
    g_log_level.store(level_from_name(name));
    get_logger().set_level(to_spdlog_level(g_log_level.load()));
}

// ---- Default: stderr backend ------------------------------------------------
#else

static std::mutex s_log_mutex;

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

void log_init(const std::string& /*ident*/) {
    // No initialisation needed for the default stderr backend.
}

void log_write(LogLevel lv, const char* tag, const char* fmt, ...) {
    char ts[16];
    timestamp(ts, sizeof(ts));

    char msg[LOG_MSG_BUF];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    std::lock_guard<std::mutex> lg(s_log_mutex);
    fprintf(stderr, "[%s][%s][%-10s] %s\n", level_str(lv), ts, tag, msg);
}

void log_set_level(const std::string& name) {
    g_log_level.store(level_from_name(name));
}

#endif // backend selection

} // namespace nids
