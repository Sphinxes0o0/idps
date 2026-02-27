#include "detection_stage.h"
#include "../core/logger.h"
#include <cstring>

namespace nids {

bool DetectionStage::process(PipelineContext& ctx) {
    PacketSlot* pkt = ctx.packet;

    // Look up / create flow entry
    auto& entry = flow_table_[pkt->flow_hash];

    // Compute current time in nanoseconds
    using namespace std::chrono;
    uint64_t now_ns = static_cast<uint64_t>(
        duration_cast<nanoseconds>(
            steady_clock::now().time_since_epoch()).count());
    uint64_t window_ns = static_cast<uint64_t>(window_ms_) * 1'000'000ULL;

    // Reset window counters when the window expires
    if (entry.window_start_ns == 0 || (now_ns - entry.window_start_ns) >= window_ns) {
        entry.window_start_ns = now_ns;
        entry.pkt_count       = 0;
        entry.byte_count      = 0;
        entry.alerted         = false;
    }

    entry.pkt_count++;
    entry.byte_count += pkt->length;

    // Store flow entry pointer in context for downstream stages
    ctx.flow_entry = &entry;

    LOG_TRACE("detection",
              "flow=0x%08X pkt_count=%u byte_count=%u threshold=%u",
              pkt->flow_hash, entry.pkt_count, entry.byte_count, pkt_threshold_);

    // DDoS: exceeded packet rate in this window
    if (entry.pkt_count >= pkt_threshold_ && !entry.alerted) {
        entry.alerted = true;
        ctx.alert     = true;
        if (ctx.matched_count < PipelineContext::MAX_RULES) {
            ctx.matched_rules[ctx.matched_count++] = -1;  // -1 = DDoS pseudo-rule
        }
        LOG_WARN("detection",
                 "DDoS ALERT flow=0x%08X pkt_count=%u >= threshold=%u",
                 pkt->flow_hash, entry.pkt_count, pkt_threshold_);
    }

    return true;  // Always continue — detection is non-blocking
}

} // namespace nids
