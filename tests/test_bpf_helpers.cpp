/* SPDX-License-Identifier: MIT */
/*
 * test_bpf_helpers.cpp - BPF Helper Functions Unit Tests (Task 37)
 *
 * Tests for BPF helper functions that can be tested from userspace.
 * These test the parsing and utility functions and structures accessible
 * from userspace code.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include "ebpf/ringbuf_reader.h"
#include "ipc/sec_event.h"
#include "core/packet.h"
#include "core/logger.h"

using namespace nids;

// ============================================================================
// AlertEvent Structure Tests
// ============================================================================

class AlertEventTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(AlertEventTest, CreateBasicEvent) {
    AlertEvent event = {};

    event.timestamp = 1000000000ULL;
    event.src_ip = 0xC0A80101;  // 192.168.1.1
    event.dst_ip = 0xC0A80102;  // 192.168.1.2
    event.src_port = 12345;
    event.dst_port = 80;
    event.protocol = 6;
    event.severity = 3;  // SEVERITY_HIGH
    event.rule_id = 1001;
    event.event_type = EVENT_RULE_MATCH;

    EXPECT_EQ(event.timestamp, 1000000000ULL);
    EXPECT_EQ(event.src_ip, 0xC0A80101u);
    EXPECT_EQ(event.dst_ip, 0xC0A80102u);
    EXPECT_EQ(event.src_port, 12345);
    EXPECT_EQ(event.dst_port, 80);
    EXPECT_EQ(event.protocol, 6);
    EXPECT_EQ(event.severity, 3u);
    EXPECT_EQ(event.rule_id, 1001u);
    EXPECT_EQ(event.event_type, EVENT_RULE_MATCH);
}

TEST_F(AlertEventTest, EventTypeValues) {
    AlertEvent event = {};

    event.event_type = EVENT_RULE_MATCH;
    EXPECT_EQ(event.event_type, 0u);

    event.event_type = EVENT_DDoS_ALERT;
    EXPECT_EQ(event.event_type, 1u);

    event.event_type = EVENT_SYN_FLOOD;
    EXPECT_EQ(event.event_type, 5u);

    event.event_type = EVENT_HTTP_DETECTED;
    EXPECT_EQ(event.event_type, 8u);

    event.event_type = EVENT_PORT_SCAN;
    EXPECT_EQ(event.event_type, 12u);

    event.event_type = EVENT_FRAG_REASSEMBLE;
    EXPECT_EQ(event.event_type, 13u);

    event.event_type = EVENT_ACK_FLOOD;
    EXPECT_EQ(event.event_type, 14u);

    event.event_type = EVENT_FIN_FLOOD;
    EXPECT_EQ(event.event_type, 15u);

    event.event_type = EVENT_RST_FLOOD;
    EXPECT_EQ(event.event_type, 16u);
}

TEST_F(AlertEventTest, Padding) {
    AlertEvent event = {};

    // Padding should be zero
    EXPECT_EQ(event.padding[0], 0u);
    EXPECT_EQ(event.padding[1], 0u);
    EXPECT_EQ(event.padding[2], 0u);
}

TEST_F(AlertEventTest, SizeOf) {
    // AlertEvent should be 32 bytes (packed)
    EXPECT_EQ(sizeof(AlertEvent), 32u);
}

// ============================================================================
// RuleEntry Structure Tests
// ============================================================================

class RuleEntryTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RuleEntryTest, CreateSimpleRule) {
    RuleEntry entry = {};

    entry.rule_id = 1001;
    entry.action = 2;  // alert
    entry.severity = 3;  // SEVERITY_HIGH
    entry.protocol = 6;  // TCP
    entry.dst_port = 80;
    entry.dst_port_max = 0;  // Single port
    entry.dpi_needed = 0;

    EXPECT_EQ(entry.rule_id, 1001u);
    EXPECT_EQ(entry.action, 2u);
    EXPECT_EQ(entry.severity, 3u);
    EXPECT_EQ(entry.protocol, 6u);
    EXPECT_EQ(entry.dst_port, 80u);
    EXPECT_EQ(entry.dst_port_max, 0u);
    EXPECT_EQ(entry.dpi_needed, 0u);
}

TEST_F(RuleEntryTest, CreatePortRangeRule) {
    RuleEntry entry = {};

    entry.rule_id = 1002;
    entry.action = 2;
    entry.severity = 2;  // SEVERITY_MEDIUM
    entry.protocol = 6;
    entry.dst_port = 8000;
    entry.dst_port_max = 8080;  // Port range
    entry.dpi_needed = 0;

    EXPECT_EQ(entry.dst_port, 8000u);
    EXPECT_EQ(entry.dst_port_max, 8080u);
}

TEST_F(RuleEntryTest, CreateDpiRule) {
    RuleEntry entry = {};

    entry.rule_id = 1003;
    entry.action = 2;
    entry.severity = 3;  // SEVERITY_HIGH
    entry.protocol = 6;
    entry.dst_port = 443;
    entry.dst_port_max = 0;
    entry.dpi_needed = 1;  // Needs DPI

    EXPECT_EQ(entry.dpi_needed, 1u);
}

TEST_F(RuleEntryTest, Padding) {
    RuleEntry entry = {};

    // Check padding is zero
    EXPECT_EQ(entry.padding[0], 0u);
    EXPECT_EQ(entry.padding[1], 0u);
}

TEST_F(RuleEntryTest, SizeOf) {
    // RuleEntry should be 12 bytes (packed)
    EXPECT_EQ(sizeof(RuleEntry), 12u);
}

// ============================================================================
// NidsConfig Tests
// ============================================================================

class NidsConfigTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(NidsConfigTest, DefaultConfig) {
    NidsConfig config = {};

    EXPECT_EQ(config.ddos_threshold, 10000u);
    EXPECT_EQ(config.window_size_ns, 1000000000u);
    EXPECT_EQ(config.enabled, 1u);
    EXPECT_EQ(config.drop_enabled, 0u);
}

TEST_F(NidsConfigTest, ModifyConfig) {
    NidsConfig config = {};

    config.ddos_threshold = 5000;
    config.enabled = 0;
    config.drop_enabled = 1;

    EXPECT_EQ(config.ddos_threshold, 5000u);
    EXPECT_EQ(config.enabled, 0u);
    EXPECT_EQ(config.drop_enabled, 1u);
}

TEST_F(NidsConfigTest, SizeOf) {
    // NidsConfig should be 20 bytes (5 * 4 bytes)
    EXPECT_EQ(sizeof(NidsConfig), 20u);
}

// ============================================================================
// PacketSlot Tests
// ============================================================================

class PacketSlotTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(PacketSlotTest, InitialState) {
    PacketSlot slot = {};

    EXPECT_EQ(slot.data, nullptr);
    EXPECT_EQ(slot.capacity, 0u);
    EXPECT_EQ(slot.length, 0u);
    EXPECT_EQ(slot.timestamp, 0u);
    EXPECT_EQ(slot.flow_hash, 0u);
    EXPECT_EQ(slot.pool_ref, nullptr);
    EXPECT_EQ(slot.eth_offset, 0u);
    EXPECT_EQ(slot.net_offset, 0u);
    EXPECT_EQ(slot.transport_offset, 0u);
    EXPECT_EQ(slot.payload_offset, 0u);
    EXPECT_EQ(slot.ip_proto, 0u);
}

TEST_F(PacketSlotTest, SetPacketData) {
    uint8_t buffer[2048];
    PacketSlot slot = {};

    slot.data = buffer;
    slot.capacity = 2048;
    slot.length = 1500;
    slot.timestamp = 1000000000ULL;
    slot.flow_hash = 0x12345678;
    slot.ip_proto = 6;  // TCP

    EXPECT_NE(slot.data, nullptr);
    EXPECT_EQ(slot.length, 1500u);
    EXPECT_EQ(slot.flow_hash, 0x12345678u);
}

TEST_F(PacketSlotTest, Reset) {
    uint8_t buffer[2048];
    PacketSlot slot = {};

    slot.data = buffer;
    slot.length = 1500;
    slot.timestamp = 1000000000ULL;
    slot.flow_hash = 0x12345678;
    slot.ip_proto = 6;

    slot.reset();

    EXPECT_EQ(slot.length, 0u);
    EXPECT_EQ(slot.timestamp, 0u);
    EXPECT_EQ(slot.flow_hash, 0u);
    EXPECT_EQ(slot.ip_proto, 0u);
}

TEST_F(PacketSlotTest, OffsetFields) {
    PacketSlot slot = {};

    slot.eth_offset = 14;
    slot.net_offset = 34;
    slot.transport_offset = 54;
    slot.payload_offset = 66;

    EXPECT_EQ(slot.eth_offset, 14u);
    EXPECT_EQ(slot.net_offset, 34u);
    EXPECT_EQ(slot.transport_offset, 54u);
    EXPECT_EQ(slot.payload_offset, 66u);
}

// ============================================================================
// PipelineContext Tests
// ============================================================================

class PipelineContextTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(PipelineContextTest, InitialState) {
    PipelineContext ctx = {};

    EXPECT_EQ(ctx.packet, nullptr);
    EXPECT_EQ(ctx.drop, false);
    EXPECT_EQ(ctx.flow_entry, nullptr);
    EXPECT_EQ(ctx.matched_count, 0);
    EXPECT_EQ(ctx.alert, false);
}

TEST_F(PipelineContextTest, Reset) {
    uint8_t buffer[2048];
    PacketSlot pkt = {};
    pkt.data = buffer;
    pkt.length = 1500;

    PipelineContext ctx = {};
    ctx.packet = &pkt;
    ctx.alert = true;
    ctx.matched_count = 2;
    ctx.matched_rules[0] = 100;
    ctx.matched_rules[1] = 200;

    ctx.reset(&pkt);

    EXPECT_EQ(ctx.packet, &pkt);
    EXPECT_EQ(ctx.drop, false);
    EXPECT_EQ(ctx.matched_count, 0);
    EXPECT_EQ(ctx.alert, false);
}

TEST_F(PipelineContextTest, MaxRules) {
    // MAX_RULES should be accessible
    EXPECT_EQ(PipelineContext::MAX_RULES, 16);
}

// ============================================================================
// SecEvent Tests
// ============================================================================

class SecEventTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(SecEventTest, InitialState) {
    SecEvent event = {};

    EXPECT_EQ(event.type, SecEvent::Type::UNKNOWN);
    EXPECT_EQ(event.timestamp, 0u);
    EXPECT_EQ(event.src_ip, 0u);
    EXPECT_EQ(event.dst_ip, 0u);
    EXPECT_EQ(event.src_port, 0u);
    EXPECT_EQ(event.dst_port, 0u);
    EXPECT_EQ(event.ip_proto, 0u);
    EXPECT_EQ(event.rule_id, -1);
}

TEST_F(SecEventTest, SetEventType) {
    SecEvent event = {};

    event.type = SecEvent::Type::DDOS;
    EXPECT_EQ(event.type, SecEvent::Type::DDOS);

    event.type = SecEvent::Type::RULE_MATCH;
    EXPECT_EQ(event.type, SecEvent::Type::RULE_MATCH);

    event.type = SecEvent::Type::LAND_ATTACK;
    EXPECT_EQ(event.type, SecEvent::Type::LAND_ATTACK);

    event.type = SecEvent::Type::INVALID_TCP_FLAGS;
    EXPECT_EQ(event.type, SecEvent::Type::INVALID_TCP_FLAGS);
}

TEST_F(SecEventTest, SetNetworkInfo) {
    SecEvent event = {};

    event.src_ip = 0xC0A80101;
    event.dst_ip = 0xC0A80102;
    event.src_port = 12345;
    event.dst_port = 80;
    event.ip_proto = 6;

    EXPECT_EQ(event.src_ip, 0xC0A80101u);
    EXPECT_EQ(event.dst_ip, 0xC0A80102u);
    EXPECT_EQ(event.src_port, 12345);
    EXPECT_EQ(event.dst_port, 80);
    EXPECT_EQ(event.ip_proto, 6);
}

TEST_F(SecEventTest, SetMessage) {
    SecEvent event = {};
    event.set_message("Test alert");

    EXPECT_NE(event.message[0], '\0');
}

// ============================================================================
// RingbufReader Tests
// ============================================================================

class RingbufReaderBasicTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RingbufReaderBasicTest, CreateWithInvalidFd) {
    RingbufReader reader(-1, [](const AlertEvent&) {});

    EXPECT_FALSE(reader.is_running());
    EXPECT_EQ(reader.get_processed_count(), 0u);
}

TEST_F(RingbufReaderBasicTest, StopBeforeStart) {
    RingbufReader reader(-1, [](const AlertEvent&) {});

    reader.stop();  // Should not crash

    EXPECT_FALSE(reader.is_running());
}

// ============================================================================
// IP Conversion Tests
// ============================================================================

class IpConversionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(IpConversionTest, BasicConversion) {
    // 192.168.1.1 = 0xC0A80101
    std::string result = ip_to_string(0xC0A80101);
    EXPECT_EQ(result, "192.168.1.1");
}

TEST_F(IpConversionTest, AnotherIp) {
    // 10.0.0.1 = 0x0A000001
    std::string result = ip_to_string(0x0A000001);
    EXPECT_EQ(result, "10.0.0.1");
}

TEST_F(IpConversionTest, Broadcast) {
    // 255.255.255.255 = 0xFFFFFFFF
    std::string result = ip_to_string(0xFFFFFFFF);
    EXPECT_EQ(result, "255.255.255.255");
}

// ============================================================================
// AlertToString Tests
// ============================================================================

class AlertToStringTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(AlertToStringTest, BasicRuleMatch) {
    AlertEvent event = {};
    event.event_type = EVENT_RULE_MATCH;
    event.rule_id = 1;
    event.severity = 3;
    event.src_ip = 0xC0A80105;
    event.dst_ip = 0x0A00000A;
    event.src_port = 54321;
    event.dst_port = 80;
    event.protocol = 6;

    std::string result = alert_to_string(event);

    EXPECT_NE(result.find("RULE_MATCH"), std::string::npos);
    EXPECT_NE(result.find("192.168.1.5"), std::string::npos);
    EXPECT_NE(result.find("10.0.0.10"), std::string::npos);
}

TEST_F(AlertToStringTest, SynFlood) {
    AlertEvent event = {};
    event.event_type = EVENT_SYN_FLOOD;
    event.severity = 4;  // CRITICAL
    event.src_ip = 0xC0A80105;
    event.dst_ip = 0x0A00000A;
    event.dst_port = 80;
    event.protocol = 6;

    std::string result = alert_to_string(event);

    EXPECT_NE(result.find("SYN_FLOOD"), std::string::npos);
}

TEST_F(AlertToStringTest, PortScan) {
    AlertEvent event = {};
    event.event_type = EVENT_PORT_SCAN;
    event.severity = 3;
    event.src_ip = 0xC0A80105;
    event.dst_ip = 0x0A00000A;
    event.protocol = 6;

    std::string result = alert_to_string(event);

    EXPECT_NE(result.find("PORT_SCAN"), std::string::npos);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}