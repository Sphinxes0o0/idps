#include <gtest/gtest.h>
#include "core/pool.hpp"
#include "core/spsc_queue.hpp"
#include "core/pipeline.h"
#include "ipc/event_queue.hpp"
#include "nic/mock_nic.h"
#include "threads/capture_thread.h"
#include "threads/processing_thread.h"
#include "threads/comm_thread.h"
#include "stages/preprocess_stage.h"
#include "stages/decode_stage.h"
#include "stages/detection_stage.h"
#include "stages/matching_stage.h"
#include "stages/event_stage.h"
#include "stages/net_headers.h"
#include <cstring>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <chrono>
#include <thread>

using namespace nids;
using namespace std::chrono_literals;

// ---- Packet builder (same as in test_stages) --------------------------------

static std::vector<uint8_t> build_tcp_pkt(
        uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
        const char* pay = nullptr, size_t plen = 0) {
    size_t total = sizeof(EthHeader) + sizeof(Ipv4Header) + sizeof(TcpHeader) + plen;
    std::vector<uint8_t> buf(total, 0);

    auto* eth    = reinterpret_cast<EthHeader*>(buf.data());
    eth->type    = htons(ETHERTYPE_IPV4);

    auto* ip     = reinterpret_cast<Ipv4Header*>(buf.data() + sizeof(EthHeader));
    ip->ihl_ver  = 0x45;
    ip->protocol = IPPROTO_TCP;
    ip->total_len = htons(static_cast<uint16_t>(sizeof(Ipv4Header) + sizeof(TcpHeader) + plen));
    ip->src      = htonl(sip);
    ip->dst      = htonl(dip);

    size_t tcp_off = sizeof(EthHeader) + sizeof(Ipv4Header);
    auto* tcp    = reinterpret_cast<TcpHeader*>(buf.data() + tcp_off);
    tcp->src_port = htons(sp);
    tcp->dst_port = htons(dp);
    tcp->data_off = 0x50;

    if (pay && plen > 0)
        std::memcpy(buf.data() + tcp_off + sizeof(TcpHeader), pay, plen);

    return buf;
}

// ---- Integration: full capture → process →event pipeline ------------------

TEST(Integration, EndToEndWithMockNic) {
    constexpr int NUM_PACKETS = 20;

    // 1. NIC: inject synthetic packets
    MockNic nic;
    const char* payload = "ATTACK payload";
    for (int i = 0; i < NUM_PACKETS; ++i) {
        nic.add_packet(build_tcp_pkt(
            0xC0A80001 + i, 0xC0A80002,
            static_cast<uint16_t>(1000 + i), 80,
            payload, std::strlen(payload)));
    }

    // 2. Infrastructure
    PacketPool             pool(256, 2048);
    SPSCQueue<PacketSlot*> queue(512);
    auto                   event_queue = std::make_shared<EventQueue>();

    // 3. Pipeline
    Pipeline pipeline;
    auto* matcher = new MatchingStage();
    matcher->add_rule({1, "attack rule", "ATTACK", IPPROTO_TCP, 0});

    pipeline.add_stage(std::make_unique<PreprocessStage>());
    pipeline.add_stage(std::make_unique<DecodeStage>());
    pipeline.add_stage(std::make_unique<DetectionStage>(9999));
    pipeline.add_stage(std::unique_ptr<IStage>(matcher));
    pipeline.add_stage(std::make_unique<EventStage>(event_queue));

    // 4. Threads
    ProcessingThread proc(pool, queue, pipeline);
    CaptureThread    cap(pool, queue, nic);

    proc.start();
    cap.start();

    // 5. Wait until all packets consumed (or timeout)
    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (nic.consumed() < static_cast<size_t>(NUM_PACKETS) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }

    // 6. Let processing drain
    std::this_thread::sleep_for(200ms);

    cap.stop();
    proc.stop();

    // 7. Verify events
    std::vector<SecEvent> events;
    event_queue->drain(events);

    EXPECT_GE(events.size(), 1u)  << "Expected at least one RULE_MATCH event";
    for (const auto& ev : events) {
        EXPECT_EQ(ev.type, SecEvent::Type::RULE_MATCH);
        EXPECT_EQ(ev.rule_id, 1);
    }

    // 8. Verify capture stats
    EXPECT_EQ(cap.stats().captured.load(), static_cast<uint64_t>(NUM_PACKETS));
    EXPECT_EQ(cap.stats().dropped_queue.load(), 0u);
}

TEST(Integration, DDoSDetection) {
    constexpr int BURST = 200;  // Above threshold=100

    MockNic nic;
    // Same 5-tuple for all packets → same flow
    for (int i = 0; i < BURST; ++i) {
        nic.add_packet(build_tcp_pkt(0xDEADBEEF, 0xCAFEBABE, 9999, 80));
    }

    PacketPool             pool(512, 2048);
    SPSCQueue<PacketSlot*> queue(1024);
    auto                   event_queue = std::make_shared<EventQueue>();

    Pipeline pipeline;
    pipeline.add_stage(std::make_unique<PreprocessStage>());
    pipeline.add_stage(std::make_unique<DecodeStage>());
    pipeline.add_stage(std::make_unique<DetectionStage>(100, 60000));  // threshold=100, 60s window
    pipeline.add_stage(std::make_unique<MatchingStage>());
    pipeline.add_stage(std::make_unique<EventStage>(event_queue));

    ProcessingThread proc(pool, queue, pipeline);
    CaptureThread    cap(pool, queue, nic);

    proc.start();
    cap.start();

    auto deadline = std::chrono::steady_clock::now() + 5s;
    while (nic.consumed() < static_cast<size_t>(BURST) &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    std::this_thread::sleep_for(200ms);

    cap.stop();
    proc.stop();

    std::vector<SecEvent> events;
    event_queue->drain(events);

    bool has_ddos = false;
    for (const auto& ev : events) {
        if (ev.type == SecEvent::Type::DDOS) has_ddos = true;
    }
    EXPECT_TRUE(has_ddos) << "Expected a DDoS event after " << BURST << " packets";
}

TEST(Integration, CommThreadWritesEvents) {
    auto eq = std::make_shared<EventQueue>();

    // Push some fake events
    for (int i = 0; i < 5; ++i) {
        SecEvent ev;
        ev.type    = SecEvent::Type::RULE_MATCH;
        ev.rule_id = i;
        ev.set_message("test event");
        eq->push(ev);
    }

    CommThread comm(eq, "-");  // "-" = stdout (captured by test runner)
    comm.start();

    std::this_thread::sleep_for(500ms);
    comm.stop();

    EXPECT_EQ(comm.events_written(), 5u);
}
