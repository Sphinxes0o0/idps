#include <gtest/gtest.h>
#include "core/logger.h"
#include <string>
#include <vector>

using namespace nids;

// ---- Test sink that captures log records ------------------------------------

struct CaptureSink : public LogSink {
    struct Record {
        LogLevel    level;
        std::string tag;
        std::string msg;
    };

    std::vector<Record> records;

    void write(LogLevel lv, const char* tag, const char* msg) override {
        records.push_back({lv, tag, msg});
    }
};

// ---- Helpers ----------------------------------------------------------------

// RAII guard: restores the original (stderr) sink after each test.
struct SinkGuard {
    ~SinkGuard() { log_set_sink(nullptr); }
};

// ---- Tests ------------------------------------------------------------------

TEST(Logger, SetSinkReceivesMessages) {
    SinkGuard guard;
    auto sink = std::make_shared<CaptureSink>();
    log_set_sink(sink);

    log_set_level("trace");
    LOG_INFO("test", "hello %s", "world");

    ASSERT_EQ(sink->records.size(), 1u);
    EXPECT_EQ(sink->records[0].level, LogLevel::INFO);
    EXPECT_EQ(sink->records[0].tag,   "test");
    EXPECT_EQ(sink->records[0].msg,   "hello world");
}

TEST(Logger, LevelFilterSuppressesMessages) {
    SinkGuard guard;
    auto sink = std::make_shared<CaptureSink>();
    log_set_sink(sink);

    log_set_level("warn");   // only WARN and ERR should pass
    LOG_DEBUG("t", "suppressed");
    LOG_INFO ("t", "suppressed");
    LOG_WARN ("t", "visible");
    LOG_ERR  ("t", "visible");

    ASSERT_EQ(sink->records.size(), 2u);
    EXPECT_EQ(sink->records[0].level, LogLevel::WARN);
    EXPECT_EQ(sink->records[1].level, LogLevel::ERR);
}

TEST(Logger, AllLevelsDeliveredWhenTrace) {
    SinkGuard guard;
    auto sink = std::make_shared<CaptureSink>();
    log_set_sink(sink);

    log_set_level("trace");
    LOG_TRACE("t", "t");
    LOG_DEBUG("t", "d");
    LOG_INFO ("t", "i");
    LOG_WARN ("t", "w");
    LOG_ERR  ("t", "e");

    EXPECT_EQ(sink->records.size(), 5u);
}

TEST(Logger, OffLevelSuppressesAll) {
    SinkGuard guard;
    auto sink = std::make_shared<CaptureSink>();
    log_set_sink(sink);

    log_set_level("off");
    LOG_TRACE("t", "x");
    LOG_DEBUG("t", "x");
    LOG_INFO ("t", "x");
    LOG_WARN ("t", "x");
    LOG_ERR  ("t", "x");

    EXPECT_EQ(sink->records.size(), 0u);
}

TEST(Logger, ResetToNullRestoresDefaultBehavior) {
    SinkGuard guard;
    auto sink = std::make_shared<CaptureSink>();
    log_set_sink(sink);
    log_set_level("info");
    LOG_INFO("t", "captured");
    ASSERT_EQ(sink->records.size(), 1u);

    // Passing nullptr should restore built-in stderr sink (no crash).
    log_set_sink(nullptr);
    EXPECT_NO_THROW(LOG_INFO("t", "goes to stderr"));
}

// Demonstrates how an spdlog-compatible adapter would look:
//
//   #include <spdlog/spdlog.h>
//   struct SpdlogSink : public nids::LogSink {
//       void write(nids::LogLevel lv, const char* tag, const char* msg) override {
//           switch (lv) {
//               case nids::LogLevel::TRACE: spdlog::trace("[{}] {}", tag, msg); break;
//               case nids::LogLevel::DEBUG: spdlog::debug("[{}] {}", tag, msg); break;
//               case nids::LogLevel::INFO:  spdlog::info ("[{}] {}", tag, msg); break;
//               case nids::LogLevel::WARN:  spdlog::warn ("[{}] {}", tag, msg); break;
//               case nids::LogLevel::ERR:   spdlog::error("[{}] {}", tag, msg); break;
//               default: break;
//           }
//       }
//   };
//   nids::log_set_sink(std::make_shared<SpdlogSink>());
//
// Demonstrates how a syslog adapter would look:
//
//   #include <syslog.h>
//   struct SyslogSink : public nids::LogSink {
//       void write(nids::LogLevel lv, const char* tag, const char* msg) override {
//           int priority = LOG_INFO;
//           switch (lv) {
//               case nids::LogLevel::TRACE: priority = LOG_DEBUG;   break;
//               case nids::LogLevel::DEBUG: priority = LOG_DEBUG;   break;
//               case nids::LogLevel::INFO:  priority = LOG_INFO;    break;
//               case nids::LogLevel::WARN:  priority = LOG_WARNING; break;
//               case nids::LogLevel::ERR:   priority = LOG_ERR;     break;
//               default: break;
//           }
//           syslog(priority, "[%s] %s", tag, msg);
//       }
//   };
//
// Demonstrates how an Android log adapter would look:
//
//   #include <android/log.h>
//   struct AndroidLogSink : public nids::LogSink {
//       const char* app_name;
//       explicit AndroidLogSink(const char* name) : app_name(name) {}
//       void write(nids::LogLevel lv, const char* tag, const char* msg) override {
//           android_LogPriority prio = ANDROID_LOG_INFO;
//           switch (lv) {
//               case nids::LogLevel::TRACE: prio = ANDROID_LOG_VERBOSE; break;
//               case nids::LogLevel::DEBUG: prio = ANDROID_LOG_DEBUG;   break;
//               case nids::LogLevel::INFO:  prio = ANDROID_LOG_INFO;    break;
//               case nids::LogLevel::WARN:  prio = ANDROID_LOG_WARN;    break;
//               case nids::LogLevel::ERR:   prio = ANDROID_LOG_ERROR;   break;
//               default: break;
//           }
//           __android_log_print(prio, app_name, "[%s] %s", tag, msg);
//       }
//   };
