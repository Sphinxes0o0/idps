#include <gtest/gtest.h>
#include "core/logger.h"

using namespace nids;

// ---- log_init ---------------------------------------------------------------

TEST(Logger, InitDoesNotCrash) {
    EXPECT_NO_FATAL_FAILURE(log_init("test-nids"));
}

// ---- log_set_level / g_log_level --------------------------------------------

TEST(Logger, SetLevelUpdatesGlobal) {
    log_set_level("trace");
    EXPECT_EQ(g_log_level.load(), LogLevel::TRACE);

    log_set_level("debug");
    EXPECT_EQ(g_log_level.load(), LogLevel::DEBUG);

    log_set_level("info");
    EXPECT_EQ(g_log_level.load(), LogLevel::INFO);

    log_set_level("warn");
    EXPECT_EQ(g_log_level.load(), LogLevel::WARN);

    log_set_level("error");
    EXPECT_EQ(g_log_level.load(), LogLevel::ERR);

    log_set_level("off");
    EXPECT_EQ(g_log_level.load(), LogLevel::OFF);

    // Restore default
    log_set_level("info");
}

TEST(Logger, UnknownLevelLeavesLevelUnchanged) {
    log_set_level("info");
    log_set_level("unknown_xyz");
    EXPECT_EQ(g_log_level.load(), LogLevel::INFO);
}

// ---- log_write --------------------------------------------------------------

TEST(Logger, WriteDoesNotCrashAtAnyLevel) {
    log_set_level("trace");
    EXPECT_NO_FATAL_FAILURE({
        log_write(LogLevel::TRACE, "test", "trace %d", 1);
        log_write(LogLevel::DEBUG, "test", "debug %s", "hello");
        log_write(LogLevel::INFO,  "test", "info message");
        log_write(LogLevel::WARN,  "test", "warn message");
        log_write(LogLevel::ERR,   "test", "error message");
    });
    log_set_level("info");
}

// ---- Convenience macros -----------------------------------------------------

TEST(Logger, MacrosDoNotCrash) {
    log_set_level("trace");
    EXPECT_NO_FATAL_FAILURE({
        LOG_TRACE("mac", "trace macro %d", 42);
        LOG_DEBUG("mac", "debug macro");
        LOG_INFO ("mac", "info macro");
        LOG_WARN ("mac", "warn macro");
        LOG_ERR  ("mac", "err macro");
    });
    log_set_level("info");
}

TEST(Logger, MacroFiltersWhenLevelTooLow) {
    // With level set to WARN, DEBUG/TRACE macros must not call log_write.
    // This is a smoke test: we verify the macros compile and execute without
    // crashing, and that the log level is not accidentally mutated by a macro.
    log_set_level("warn");
    LOG_DEBUG("filter", "this should be filtered");
    LOG_TRACE("filter", "this should be filtered");
    EXPECT_EQ(g_log_level.load(), LogLevel::WARN);  // level must be unchanged

    log_set_level("info");
}
