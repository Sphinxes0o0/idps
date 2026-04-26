/* SPDX-License-Identifier: MIT */
/*
 * test_ebpf_loader.cpp - eBPF Loader 单元测试
 *
 * 注意: 这些测试需要 Linux 环境并安装了 libbpf
 */

#include <gtest/gtest.h>
#include "ebpf/ebpf_loader.h"
#include "ebpf/ringbuf_reader.h"

namespace nids {
namespace testing {

class EbpfLoaderTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(EbpfLoaderTest, CreateAndDestroy) {
    EbpfLoader loader;
    EXPECT_FALSE(loader.is_loaded());
}

TEST_F(EbpfLoaderTest, GetMapFdBeforeLoad) {
    EbpfLoader loader;
    EXPECT_EQ(loader.get_map_fd("rules"), -1);
    EXPECT_EQ(loader.get_map_fd("stats"), -1);
    EXPECT_EQ(loader.get_map_fd("events"), -1);
}

TEST_F(EbpfLoaderTest, UpdateConfig) {
    EbpfLoader loader;
    NidsConfig config;
    config.ddos_threshold = 5000;
    config.enabled = true;

    // 在加载前更新配置应该失败
    EXPECT_FALSE(loader.update_config(config));
}

TEST_F(EbpfLoaderTest, GetStats) {
    EbpfLoader loader;
    EXPECT_EQ(loader.get_stat(0), 0);
    EXPECT_EQ(loader.get_stat(1), 0);
    EXPECT_EQ(loader.get_stat(100), 0);
}

class RingbufReaderTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RingbufReaderTest, CreateAndDestroy) {
    // 无效的 fd
    RingbufReader reader(-1, [](const AlertEvent&) {});
    EXPECT_FALSE(reader.is_running());
}

TEST_F(RingbufReaderTest, StopBeforeStart) {
    RingbufReader reader(-1, [](const AlertEvent&) {});
    reader.stop();  // 应该不崩溃
    EXPECT_FALSE(reader.is_running());
}

TEST_F(RingbufReaderTest, ProcessedCount) {
    RingbufReader reader(-1, [](const AlertEvent&) {});
    EXPECT_EQ(reader.get_processed_count(), 0);
}

// 测试辅助函数
TEST(AlertToString, BasicConversion) {
    AlertEvent event = {};
    event.event_type = EVENT_RULE_MATCH;
    event.rule_id = 1;
    event.severity = 3;  // SEVERITY_HIGH = 3
    event.src_ip = 0xC0A80105;  // 192.168.1.5
    event.dst_ip = 0x0A00000A;  // 10.0.0.10
    event.src_port = 54321;
    event.dst_port = 80;
    event.protocol = 6;  // TCP

    std::string result = alert_to_string(event);
    EXPECT_NE(result.find("RULE_MATCH"), std::string::npos);
    EXPECT_NE(result.find("192.168.1.5"), std::string::npos);
    EXPECT_NE(result.find("10.0.0.10"), std::string::npos);
}

TEST(IpToString, BasicConversion) {
    EXPECT_EQ(ip_to_string(0xC0A80105), "192.168.1.5");
    EXPECT_EQ(ip_to_string(0x0A00000A), "10.0.0.10");
    EXPECT_EQ(ip_to_string(0xFFFFFFFF), "255.255.255.255");
}

} // namespace testing
} // namespace nids

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
