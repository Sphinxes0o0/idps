#pragma once
#include <cstdint>
#include <cstring>

namespace nids {

// Supported slot data sizes
enum class SlotSize : uint32_t {
    SMALL  = 256,
    MEDIUM = 512,
    LARGE  = 1024,
    JUMBO  = 2048,
};

/**
 * @brief PacketSlot — the central data container passing through the pipeline.
 *
 * Designed to be POD-like for cache efficiency.  Actual byte storage is owned
 * by the PacketPool slab; only a raw pointer is stored here.
 */
struct PacketSlot {
    uint8_t*  data       = nullptr;   ///< Pointer into pool slab
    uint32_t  capacity   = 0;         ///< Buffer size in bytes
    uint32_t  length     = 0;         ///< Captured packet length
    uint64_t  timestamp  = 0;         ///< Nanoseconds since epoch (set by capture)
    uint32_t  flow_hash  = 0;         ///< Pre-calculated 5-tuple hash
    void*     pool_ref   = nullptr;   ///< Back-pointer to owning PacketPool

    // Decoded network layer offsets (populated by DecodeStage)
    uint16_t  eth_offset  = 0;
    uint16_t  net_offset  = 0;   ///< IP header offset
    uint16_t  transport_offset = 0;
    uint16_t  payload_offset   = 0;
    uint8_t   ip_proto   = 0;   ///< IPPROTO_TCP / IPPROTO_UDP / etc.

    void reset() noexcept {
        length          = 0;
        timestamp       = 0;
        flow_hash       = 0;
        eth_offset      = 0;
        net_offset      = 0;
        transport_offset = 0;
        payload_offset  = 0;
        ip_proto        = 0;
    }
};

/**
 * @brief PipelineContext — transient state attached to one packet as it moves
 * through the pipeline stages.
 */
struct PipelineContext {
    PacketSlot* packet   = nullptr;
    bool        drop     = false;   ///< Set to true by any stage to abort processing

    // Stage-populated fields
    void*       flow_entry = nullptr;  ///< Pointer into FlowTable (set by DetectionStage)

    // Matched rule IDs filled by MatchingStage
    static constexpr int MAX_RULES = 16;
    int   matched_rules[MAX_RULES] = {};
    int   matched_count = 0;

    bool alert = false;   ///< True when any detection / matching fired

    void reset(PacketSlot* pkt) noexcept {
        packet        = pkt;
        drop          = false;
        flow_entry    = nullptr;
        matched_count = 0;
        alert         = false;
    }
};

} // namespace nids
