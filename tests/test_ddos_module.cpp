#include <gtest/gtest.h>
#include "core/packet.h"
#include "core/pool.hpp"
#include "stages/decode_stage.h"
#include "stages/detection_stage.h"
#include "stages/net_headers.h"
#include <cstring>
#include <arpa/inet.h>
#include <thread>
#include <fstream>
#include <cstdio>

using namespace nids;

// Helper to build packet
static void simple_packet(PacketSlot* slot, uint32_t src_ip, uint32_t dst_ip, 
                          uint16_t sport, uint16_t dport, uint8_t proto) {
    // Reset
    std::memset(slot->data, 0, slot->capacity);
    
    // Header Pointers
    auto* eth = reinterpret_cast<EthHeader*>(slot->data);
    auto* ip  = reinterpret_cast<Ipv4Header*>(slot->data + sizeof(EthHeader));
    // Assume minimal headers
    
    // Eth
    eth->type = htons(0x0800);
    
    // IP
    ip->ihl_ver = 0x45;
    ip->total_len = htons(sizeof(Ipv4Header) + 20); // 20 bytes payload/transport
    ip->protocol = proto;
    ip->src = htonl(src_ip);
    ip->dst = htonl(dst_ip);
    
    // Transport (just ports for now)
    uint8_t* t_ptr = slot->data + sizeof(EthHeader) + sizeof(Ipv4Header);
    uint16_t* ports = reinterpret_cast<uint16_t*>(t_ptr);
    ports[0] = htons(sport); // src
    ports[1] = htons(dport); // dst

    slot->length = sizeof(EthHeader) + sizeof(Ipv4Header) + 20;
}

TEST(DDoSModuleTest, SnortRules) {
    // Setup
    PacketPool pool(16, 2048);
    PipelineContext ctx;
    ctx.packet = pool.allocate();

    DecodeStage decoder;
    DetectionStage detector(1000, 1000); // 10000 global threshold (effectively disabled for this test)

    ASSERT_TRUE(detector.load_rules("tests/ddos.rules"));
    
    // Test Rule: TCP any any -> any 80 (count 5, seconds 2)
    uint32_t attacker_ip = 0x01020304; // 1.2.3.4
    uint32_t victim_ip   = 0x05060708; // 5.6.7.8

    // Send 4 packets - No Alert
    for (int i=0; i<4; ++i) {
        simple_packet(ctx.packet, attacker_ip, victim_ip, 1234 + i, 80, IPPROTO_TCP);
        ctx.reset(ctx.packet);
        
        decoder.process(ctx);
        detector.process(ctx);
        
        EXPECT_FALSE(ctx.alert) << "Packet " << i+1 << " should not trigger alert";
    }

    // Send 5th packet - Alert!
    simple_packet(ctx.packet, attacker_ip, victim_ip, 1238, 80, IPPROTO_TCP);
    ctx.reset(ctx.packet);
    decoder.process(ctx);
    detector.process(ctx);
    EXPECT_TRUE(ctx.alert) << "Packet 5 should trigger alert";
    
    // Verify Rule ID matched
    bool matched_sid = false;
    for(int i=0; i<ctx.matched_count; ++i) {
        if(ctx.matched_rules[i] == 101) matched_sid = true;
    }
    EXPECT_TRUE(matched_sid);

    // Send 6th packet - No new alert (already alerted state in window)
    // Note: ctx.alert might be true if global detection fired, but here we check logic
    // My implementation sets ctx.alert = true ONLY on the edge (when crossing threshold).
    simple_packet(ctx.packet, attacker_ip, victim_ip, 1239, 80, IPPROTO_TCP);
    ctx.reset(ctx.packet);
    decoder.process(ctx);
    detector.process(ctx);
    // Wait, in my code: if (count >= limit && !alerted) -> alert=true.
    // If alerted is true, it skips setting alert=true.
    EXPECT_FALSE(ctx.alert) << "Packet 6 should not re-trigger alert in same window";
}

TEST(DDoSModuleTest, TrackBySrc) {
    // track by_src: flows from different SRCs should have independent counters
    PacketPool pool(16, 2048);
    PipelineContext ctx;
    ctx.packet = pool.allocate();

    DecodeStage decoder;
    DetectionStage detector(1000, 1000);
    ASSERT_TRUE(detector.load_rules("tests/ddos.rules"));

    // Rule 101: count 5
    
    // Attacker A: 4 packets
    for (int i=0; i<4; ++i) {
        simple_packet(ctx.packet, 0x0A000001, 0x05050505, 1000+i, 80, IPPROTO_TCP);
        ctx.reset(ctx.packet);
        decoder.process(ctx);
        detector.process(ctx);
        EXPECT_FALSE(ctx.alert);
    }
    
    // Attacker B: 4 packets (should not sum with A)
    for (int i=0; i<4; ++i) {
        simple_packet(ctx.packet, 0x0A000002, 0x05050505, 1000+i, 80, IPPROTO_TCP);
        ctx.reset(ctx.packet);
        decoder.process(ctx);
        detector.process(ctx);
        EXPECT_FALSE(ctx.alert) << "Attacker B should be independent";
    }

    // Attacker A: 5th packet -> Alert
    simple_packet(ctx.packet, 0x0A000001, 0x05050505, 1005, 80, IPPROTO_TCP);
    ctx.reset(ctx.packet);
    decoder.process(ctx);
    detector.process(ctx);
    EXPECT_TRUE(ctx.alert);
    // Check SID
    EXPECT_EQ(ctx.matched_rules[0], 101);
}

TEST(DDoSModuleTest, DetectionFilterSyntaxSupported) {
    const char* rule_path = "/tmp/idps_ddos_detection_filter.rules";
    {
        std::ofstream out(rule_path);
        out << "alert tcp any any -> any 80 (msg:\"HTTP Flood DF\"; detection_filter: track by_src, count 3, seconds 2; sid:201;)\n";
    }

    PacketPool pool(16, 2048);
    PipelineContext ctx;
    ctx.packet = pool.allocate();

    DecodeStage decoder;
    DetectionStage detector(1000, 1000);
    ASSERT_TRUE(detector.load_rules(rule_path));

    for (int i = 0; i < 2; ++i) {
        simple_packet(ctx.packet, 0x0A000010, 0x0A000001, 4000 + i, 80, IPPROTO_TCP);
        ctx.reset(ctx.packet);
        decoder.process(ctx);
        detector.process(ctx);
        EXPECT_FALSE(ctx.alert);
    }

    simple_packet(ctx.packet, 0x0A000010, 0x0A000001, 4002, 80, IPPROTO_TCP);
    ctx.reset(ctx.packet);
    decoder.process(ctx);
    detector.process(ctx);
    EXPECT_TRUE(ctx.alert);

    std::remove(rule_path);
}

TEST(DDoSModuleTest, InvalidThresholdRuleIgnored) {
    const char* rule_path = "/tmp/idps_ddos_invalid.rules";
    {
        std::ofstream out(rule_path);
        out << "alert tcp any any -> any 80 (msg:\"bad\"; threshold: track by_src, count 0, seconds 0; sid:301;)\n";
    }

    PacketPool pool(16, 2048);
    PipelineContext ctx;
    ctx.packet = pool.allocate();

    DecodeStage decoder;
    DetectionStage detector(1000, 1000);
    ASSERT_TRUE(detector.load_rules(rule_path));

    for (int i = 0; i < 10; ++i) {
        simple_packet(ctx.packet, 0x0A000020, 0x0A000001, 5000 + i, 80, IPPROTO_TCP);
        ctx.reset(ctx.packet);
        decoder.process(ctx);
        detector.process(ctx);
        EXPECT_FALSE(ctx.alert);
    }

    std::remove(rule_path);
}

