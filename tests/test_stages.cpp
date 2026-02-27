#include <gtest/gtest.h>
#include "core/packet.h"
#include "core/pool.hpp"
#include "stages/preprocess_stage.h"
#include "stages/decode_stage.h"
#include "stages/detection_stage.h"
#include "stages/matching_stage.h"
#include "stages/event_stage.h"
#include "stages/net_headers.h"
#include "ipc/event_queue.hpp"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>  // IPPROTO_TCP / UDP

using namespace nids;

// ---- Helpers ----------------------------------------------------------------

// Build a minimal IPv4/TCP packet inside a buffer.
// Returns the total length.
static size_t build_ipv4_tcp(uint8_t* buf, size_t buf_cap,
                               uint32_t src_ip, uint32_t dst_ip,
                               uint16_t sport, uint16_t dport,
                               const char* payload = nullptr,
                               size_t pay_len = 0) {
    if (buf_cap < sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + pay_len)
        return 0;

    // Ethernet
    auto* eth    = reinterpret_cast<EthHeader*>(buf);
    std::memset(eth, 0, sizeof(*eth));
    eth->type    = htons(ETHERTYPE_IPV4);

    // IPv4
    size_t ip_off = sizeof(EthHeader);
    auto* ip      = reinterpret_cast<Ipv4Header*>(buf + ip_off);
    std::memset(ip, 0, sizeof(*ip));
    ip->ihl_ver   = 0x45;  // version=4, IHL=5 (20 bytes)
    ip->protocol  = IPPROTO_TCP;
    ip->total_len = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(TcpHeader) + pay_len));
    ip->src       = htonl(src_ip);
    ip->dst       = htonl(dst_ip);

    // TCP
    size_t tcp_off = ip_off + sizeof(Ipv4Header);
    auto* tcp      = reinterpret_cast<TcpHeader*>(buf + tcp_off);
    std::memset(tcp, 0, sizeof(*tcp));
    tcp->src_port  = htons(sport);
    tcp->dst_port  = htons(dport);
    tcp->data_off  = 0x50;  // 5 * 4 = 20 bytes header

    // Payload
    size_t pay_off = tcp_off + sizeof(TcpHeader);
    if (payload && pay_len > 0)
        std::memcpy(buf + pay_off, payload, pay_len);

    return pay_off + pay_len;
}

// Helper: create a context with a real packet in a pool slot
struct TestCtx {
    PacketPool      pool{4, 2048};
    PacketSlot*     slot   = nullptr;
    PipelineContext ctx;

    TestCtx() { slot = pool.allocate(); ctx.reset(slot); }
    ~TestCtx() { if (slot) pool.free(slot); }

    void load_tcp(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                  const char* pay = nullptr, size_t plen = 0) {
        size_t len = build_ipv4_tcp(slot->data, slot->capacity,
                                    sip, dip, sp, dp, pay, plen);
        slot->length = static_cast<uint32_t>(len);
    }
};

// ============================================================
// PreprocessStage
// ============================================================

TEST(PreprocessStage, PassNormalPacket) {
    TestCtx t;
    t.load_tcp(0xC0A80001, 0xC0A80002, 1234, 80);
    PreprocessStage stage;
    EXPECT_TRUE(stage.process(t.ctx));
    EXPECT_FALSE(t.ctx.drop);
}

TEST(PreprocessStage, DropTooShort) {
    TestCtx t;
    t.slot->length = 5;  // Less than 14 bytes
    PreprocessStage stage;
    EXPECT_FALSE(stage.process(t.ctx));
    EXPECT_TRUE(t.ctx.drop);
}

TEST(PreprocessStage, DropTooLong) {
    TestCtx t;
    t.slot->length = 70000;
    PreprocessStage stage;
    EXPECT_FALSE(stage.process(t.ctx));
    EXPECT_TRUE(t.ctx.drop);
}

// ============================================================
// DecodeStage
// ============================================================

TEST(DecodeStage, DecodesIPv4TCP) {
    TestCtx t;
    t.load_tcp(0x0A000001, 0x0A000002, 4321, 443);

    PreprocessStage pre;
    DecodeStage     dec;
    ASSERT_TRUE(pre.process(t.ctx));
    ASSERT_TRUE(dec.process(t.ctx));
    EXPECT_FALSE(t.ctx.drop);
    EXPECT_EQ(t.slot->ip_proto, static_cast<uint8_t>(IPPROTO_TCP));
    EXPECT_GT(t.slot->flow_hash, 0u);
    EXPECT_GT(t.slot->payload_offset, t.slot->transport_offset);
}

TEST(DecodeStage, DropNonIPv4) {
    TestCtx t;
    uint8_t* buf = t.slot->data;
    auto* eth = reinterpret_cast<EthHeader*>(buf);
    std::memset(eth, 0, sizeof(*eth));
    eth->type = htons(ETHERTYPE_ARP);    // ARP not supported
    t.slot->length = sizeof(EthHeader) + 28;  // valid ARP size

    DecodeStage dec;
    bool ok = dec.process(t.ctx);
    EXPECT_FALSE(ok);
    EXPECT_TRUE(t.ctx.drop);
}

TEST(DecodeStage, FlowHashDifferentForDifferentFlows) {
    TestCtx t1, t2;
    t1.load_tcp(0x01020304, 0x05060708, 100, 80);
    t2.load_tcp(0x01020304, 0x05060708, 200, 80);  // different src port

    PreprocessStage pre;
    DecodeStage     dec;

    pre.process(t1.ctx); dec.process(t1.ctx);
    pre.process(t2.ctx); dec.process(t2.ctx);

    EXPECT_NE(t1.slot->flow_hash, t2.slot->flow_hash);
}

// ============================================================
// DetectionStage
// ============================================================

TEST(DetectionStage, NoAlertBelowThreshold) {
    TestCtx t;
    t.load_tcp(1, 2, 100, 80);
    PreprocessStage pre; DecodeStage dec; DetectionStage det(100);
    pre.process(t.ctx); dec.process(t.ctx); det.process(t.ctx);
    EXPECT_FALSE(t.ctx.alert);
}

TEST(DetectionStage, AlertAtThreshold) {
    DetectionStage det(5, 60000);  // 5 pkt threshold, 60s window
    PacketPool pool(64, 2048);

    bool alerted = false;
    for (int i = 0; i < 10; ++i) {
        auto* s = pool.allocate();
        build_ipv4_tcp(s->data, s->capacity, 0x01020304, 0x05060708, 9999, 80);
        s->length = static_cast<uint32_t>(
            sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader));

        PipelineContext ctx;
        ctx.reset(s);
        PreprocessStage pre; DecodeStage dec;
        pre.process(ctx); dec.process(ctx); det.process(ctx);
        if (ctx.alert) alerted = true;
        pool.free(s);
    }
    EXPECT_TRUE(alerted);
}

// ============================================================
// MatchingStage
// ============================================================

TEST(MatchingStage, MatchesContent) {
    MatchingStage m;
    m.add_rule({1, "test content rule", "evil", IPPROTO_TCP, 80});

    const char* payload = "GET /evil HTTP/1.1\r\n";
    TestCtx t;
    t.load_tcp(1, 2, 1234, 80, payload, std::strlen(payload));

    PreprocessStage pre; DecodeStage dec;
    pre.process(t.ctx); dec.process(t.ctx);
    m.process(t.ctx);

    EXPECT_TRUE(t.ctx.alert);
    EXPECT_EQ(t.ctx.matched_count, 1);
    EXPECT_EQ(t.ctx.matched_rules[0], 1);
}

TEST(MatchingStage, NoMatchWrongPort) {
    MatchingStage m;
    m.add_rule({2, "port 443 rule", "secret", IPPROTO_TCP, 443});

    const char* payload = "GET /secret HTTP/1.1\r\n";
    TestCtx t;
    t.load_tcp(1, 2, 1234, 80, payload, std::strlen(payload));  // port 80, not 443

    PreprocessStage pre; DecodeStage dec;
    pre.process(t.ctx); dec.process(t.ctx);
    m.process(t.ctx);

    EXPECT_FALSE(t.ctx.alert);
    EXPECT_EQ(t.ctx.matched_count, 0);
}

TEST(MatchingStage, EmptyContentMatchesAll) {
    MatchingStage m;
    m.add_rule({3, "any-traffic rule", "" /*empty = match all*/, 0, 0});

    const char* payload = "hello";
    TestCtx t;
    t.load_tcp(1, 2, 5000, 8080, payload, 5);

    PreprocessStage pre; DecodeStage dec;
    pre.process(t.ctx); dec.process(t.ctx);
    m.process(t.ctx);

    EXPECT_TRUE(t.ctx.alert);
}

// ============================================================
// EventStage
// ============================================================

TEST(EventStage, PushesEventOnAlert) {
    auto eq = std::make_shared<EventQueue>();
    EventStage ev(eq);

    TestCtx t;
    t.load_tcp(0xC0000001, 0xC0000002, 1111, 80);
    PreprocessStage pre; DecodeStage dec;
    pre.process(t.ctx); dec.process(t.ctx);

    t.ctx.alert = true;
    t.ctx.matched_rules[t.ctx.matched_count++] = 42;

    ev.process(t.ctx);
    EXPECT_EQ(eq->size(), 1u);

    auto maybe = eq->pop(0);
    ASSERT_TRUE(maybe.has_value());
    EXPECT_EQ(maybe->rule_id, 42);
    EXPECT_EQ(maybe->dst_port, 80u);
}

TEST(EventStage, NoPushWithoutAlert) {
    auto eq = std::make_shared<EventQueue>();
    EventStage ev(eq);

    TestCtx t;
    t.load_tcp(1, 2, 100, 200);
    PreprocessStage pre; DecodeStage dec;
    pre.process(t.ctx); dec.process(t.ctx);
    // ctx.alert stays false

    ev.process(t.ctx);
    EXPECT_EQ(eq->size(), 0u);
}
