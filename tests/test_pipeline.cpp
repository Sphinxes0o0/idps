#include <gtest/gtest.h>
#include "core/pipeline.h"
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
#include <netinet/in.h>

using namespace nids;

// ---- Helper: build a minimal TCP packet ------------------------------------

static size_t make_tcp_pkt(uint8_t* buf, size_t cap,
                            uint32_t sip, uint32_t dip,
                            uint16_t sp,  uint16_t dp,
                            const char* pay = nullptr, size_t plen = 0) {
    if (cap < sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + plen)
        return 0;

    auto* eth    = reinterpret_cast<EthHeader*>(buf);
    std::memset(eth, 0, sizeof(*eth));
    eth->type    = htons(ETHERTYPE_IPV4);

    auto* ip     = reinterpret_cast<Ipv4Header*>(buf + sizeof(EthHeader));
    std::memset(ip, 0, sizeof(*ip));
    ip->ihl_ver  = 0x45;
    ip->protocol = IPPROTO_TCP;
    ip->total_len = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(TcpHeader) + plen));
    ip->src      = htonl(sip);
    ip->dst      = htonl(dip);

    size_t tcp_off = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp    = reinterpret_cast<TcpHeader*>(buf + tcp_off);
    std::memset(tcp, 0, sizeof(*tcp));
    tcp->src_port = htons(sp);
    tcp->dst_port = htons(dp);
    tcp->data_off = 0x50;

    if (pay && plen > 0)
        std::memcpy(buf + tcp_off + sizeof(TcpHeader), pay, plen);

    return tcp_off + sizeof(TcpHeader) + plen;
}

// ---- Tests ------------------------------------------------------------------

TEST(Pipeline, InitAndExecuteBasic) {
    Pipeline p;
    p.add_stage(std::make_unique<PreprocessStage>());
    p.add_stage(std::make_unique<DecodeStage>());
    EXPECT_TRUE(p.init());

    PacketPool pool(4, 2048);
    auto* slot = pool.allocate();
    size_t len = make_tcp_pkt(slot->data, slot->capacity,
                               0x01010101, 0x02020202, 5000, 80);
    slot->length = static_cast<uint32_t>(len);

    p.execute(slot);  // Should not crash
    EXPECT_GT(slot->flow_hash, 0u);
    pool.free(slot);
}

TEST(Pipeline, EarlyDropOnPreprocess) {
    int process_count = 0;

    // Dummy stage that counts calls
    struct CountStage : IStage {
        int& cnt;
        explicit CountStage(int& c) : cnt(c) {}
        bool process(PipelineContext&) override { cnt++; return true; }
        std::string name() const override { return "Counter"; }
    };

    Pipeline p;
    p.add_stage(std::make_unique<PreprocessStage>());
    p.add_stage(std::make_unique<CountStage>(process_count));
    EXPECT_TRUE(p.init());

    PacketPool pool(2, 2048);
    auto* slot = pool.allocate();
    slot->length = 5;  // Too short — preprocess will drop

    p.execute(slot);
    EXPECT_EQ(process_count, 0) << "CountStage should not have run";
    pool.free(slot);
}

TEST(Pipeline, StatsTracked) {
    Pipeline p;
    p.add_stage(std::make_unique<PreprocessStage>());
    p.add_stage(std::make_unique<DecodeStage>());
    EXPECT_TRUE(p.init());

    PacketPool pool(4, 2048);
    for (int i = 0; i < 5; ++i) {
        auto* slot = pool.allocate();
        size_t len = make_tcp_pkt(slot->data, slot->capacity,
                                   0x01020304, 0x05060708, 1000, 443);
        slot->length = static_cast<uint32_t>(len);
        p.execute(slot);
        pool.free(slot);
    }

    EXPECT_EQ(p.stages()[0]->stats.processed.load(), 5u);
    EXPECT_EQ(p.stages()[1]->stats.processed.load(), 5u);
}

TEST(Pipeline, FullPipelineWithMatch) {
    auto eq = std::make_shared<EventQueue>();
    auto* matcher = new MatchingStage();
    matcher->add_rule({99, "test", "HACK", IPPROTO_TCP, 0});

    Pipeline p;
    p.add_stage(std::make_unique<PreprocessStage>());
    p.add_stage(std::make_unique<DecodeStage>());
    p.add_stage(std::make_unique<DetectionStage>(99999));
    p.add_stage(std::unique_ptr<IStage>(matcher));
    p.add_stage(std::make_unique<EventStage>(eq));
    EXPECT_TRUE(p.init());

    const char* payload = "HACK the planet";
    PacketPool pool(4, 2048);
    auto* slot = pool.allocate();
    size_t len = make_tcp_pkt(slot->data, slot->capacity,
                               0xACE00001, 0xBEEF0002, 8888, 80,
                               payload, std::strlen(payload));
    slot->length = static_cast<uint32_t>(len);

    p.execute(slot);
    pool.free(slot);

    EXPECT_EQ(eq->size(), 1u);
    auto ev = eq->pop(0);
    ASSERT_TRUE(ev.has_value());
    EXPECT_EQ(ev->rule_id, 99);
}

TEST(Pipeline, Shutdown) {
    Pipeline p;
    p.add_stage(std::make_unique<PreprocessStage>());
    EXPECT_TRUE(p.init());
    p.shutdown();  // Must not throw
}
