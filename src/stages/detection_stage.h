#pragma once
#include "../core/stage.h"
#include "net_headers.h"
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <atomic>
#include <vector>
#include <string>

namespace nids {

/**
 * @brief FlowEntry — tracks per-flow state for DDoS detection.
 *
 * Uses a simple fixed-window packet counter.  When the counter
 * exceeds `threshold` within `window_ms` milliseconds, a DDoS
 * event is raised.
 */
struct FlowEntry {
    uint64_t window_start_ns = 0;
    uint32_t pkt_count       = 0;
    uint32_t byte_count      = 0;
    bool     alerted         = false;  ///< Suppress duplicate events
};

enum class TrackType {
    BY_SRC,
    BY_DST
};

struct DdosRule {
    int         sid = 0;
    std::string msg;
    
    // Filter conditions (0 = any)
    uint8_t     proto = 0;
    uint32_t    src_ip = 0;  // Network byte order
    uint32_t    dst_ip = 0;
    uint16_t    src_port = 0;
    uint16_t    dst_port = 0;
    
    // Threshold config
    uint32_t    limit_count = 0;
    uint32_t    limit_seconds = 0;
    TrackType   track = TrackType::BY_SRC;
};

/**
 * @brief DetectionStage — stateful per-flow DDoS detection.
 *
 * One flow is identified by (src_ip, dst_ip, src_port, dst_port, proto).
 * A hash is computed by DecodeStage and stored in PacketSlot::flow_hash.
 *
 * Thread safety: each pipeline (= each NIC) owns its own DetectionStage,
 * so no locking is needed for the flow table itself.
 */
class DetectionStage : public IStage {
public:
    /**
     * @param pkt_threshold  Max packets per window before alert.
     * @param window_ms      Measurement window in milliseconds.
     */
    explicit DetectionStage(uint32_t pkt_threshold = 10000,
                            uint32_t window_ms     = 1000)
        : pkt_threshold_(pkt_threshold), window_ms_(window_ms) {}

    bool init()                        override { return true; }
    bool process(PipelineContext& ctx)  override;
    std::string name() const           override { return "Detection"; }
    void shutdown()                    override { 
        flow_table_.clear(); 
        rule_states_.clear();
    }

    bool load_rules(const std::string& path);
    size_t flow_count() const { return flow_table_.size(); }

private:
    uint32_t pkt_threshold_;
    uint32_t window_ms_;

    // Keyed by PacketSlot::flow_hash (good enough for one-NIC pipeline)
    std::unordered_map<uint32_t, FlowEntry> flow_table_;

    std::vector<DdosRule> rules_;
    std::unordered_map<std::string, FlowEntry> rule_states_;
};

} // namespace nids
