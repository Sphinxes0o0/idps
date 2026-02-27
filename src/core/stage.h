#pragma once
#include "packet.h"
#include <string>
#include <atomic>

namespace nids {

/**
 * @brief Per-stage performance counters (updated by the pipeline executor).
 */
struct StageStats {
    std::atomic<uint64_t> processed{0};   ///< Packets that entered this stage
    std::atomic<uint64_t> dropped{0};     ///< Packets dropped by this stage
    std::atomic<uint64_t> ns_total{0};    ///< Total nanoseconds spent in stage

    StageStats() = default;
    // Atomic types are not movable by default — provide explicit move ctor
    StageStats(StageStats&& o) noexcept
        : processed(o.processed.load()), dropped(o.dropped.load()), ns_total(o.ns_total.load()) {}
};

/**
 * @brief Abstract interface for a single pipeline processing stage.
 *
 * Lifecycle:
 *   1. init()    — called once before the pipeline starts.
 *   2. process() — called per packet on the processing thread.
 *   3. shutdown()— called once when the pipeline stops.
 *
 * Return convention for process():
 *   - true  → continue to next stage.
 *   - false → abort pipeline for this packet (equivalent to ctx.drop = true).
 */
class IStage {
public:
    virtual ~IStage() = default;

    /** @brief One-time initialisation. Return false to block pipeline start. */
    virtual bool init() { return true; }

    /** @brief Per-packet work. */
    virtual bool process(PipelineContext& ctx) = 0;

    /** @brief Cleanup on pipeline stop. */
    virtual void shutdown() {}

    /** @brief Human-readable name used in logs and metrics. */
    virtual std::string name() const = 0;

    StageStats stats;
};

} // namespace nids
