#include "preprocess_stage.h"
#include "../core/logger.h"

namespace nids {

bool PreprocessStage::process(PipelineContext& ctx) {
    PacketSlot* pkt = ctx.packet;

    // Guard against null
    if (!pkt || !pkt->data) {
        LOG_WARN("preprocess", "null packet or data pointer — dropped");
        ctx.drop = true;
        return false;
    }

    // Too short to contain a valid Ethernet header
    if (pkt->length < MIN_FRAME) {
        LOG_DEBUG("preprocess", "pkt too short: %u bytes (min %u) — dropped",
                  pkt->length, MIN_FRAME);
        ctx.drop = true;
        return false;
    }

    // Sanity ceiling (shouldn't happen with a well-configured NIC buffer)
    if (pkt->length > MAX_FRAME) {
        LOG_DEBUG("preprocess", "pkt too long: %u bytes (max %u) — dropped",
                  pkt->length, MAX_FRAME);
        ctx.drop = true;
        return false;
    }

    LOG_TRACE("preprocess", "pkt len=%u — OK", pkt->length);
    return true;  // Pass to next stage
}

} // namespace nids
