#pragma once
#include "stage.h"
#include <vector>
#include <memory>
#include <string>
#include <chrono>

namespace nids {

/**
 * @brief Ordered chain of IStage instances.
 *
 * The pipeline is single-threaded when executing (one processing thread drives
 * it) and must not be mutated after start().
 *
 * Usage:
 *   Pipeline p;
 *   p.add_stage(std::make_unique<PreprocessStage>());
 *   p.add_stage(std::make_unique<DecodeStage>());
 *   p.init();
 *   p.execute(pkt);
 *   p.shutdown();
 */
class Pipeline {
public:
    /**
     * @brief Append a stage to the end of the chain.
     * Call before init().
     */
    void add_stage(std::unique_ptr<IStage> stage) {
        stages_.push_back(std::move(stage));
    }

    /**
     * @brief Initialise all stages in order.
     * @return false if any stage fails to initialise.
     */
    bool init() {
        for (auto& s : stages_) {
            if (!s->init()) return false;
        }
        return true;
    }

    /**
     * @brief Execute all stages for one packet.
     * Stops early if any stage returns false or sets ctx.drop.
     */
    void execute(PacketSlot* packet) {
        ctx_.reset(packet);
        for (auto& stage : stages_) {
            auto t0 = now_ns();
            bool ok = stage->process(ctx_);
            stage->stats.ns_total.fetch_add(now_ns() - t0, std::memory_order_relaxed);
            stage->stats.processed.fetch_add(1, std::memory_order_relaxed);

            if (!ok || ctx_.drop) {
                stage->stats.dropped.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
    }

    /** @brief Orderly shutdown of all stages. */
    void shutdown() {
        for (auto& s : stages_) s->shutdown();
    }

    const std::vector<std::unique_ptr<IStage>>& stages() const { return stages_; }

private:
    static uint64_t now_ns() noexcept {
        using namespace std::chrono;
        return static_cast<uint64_t>(
            duration_cast<nanoseconds>(
                steady_clock::now().time_since_epoch()).count());
    }

    std::vector<std::unique_ptr<IStage>> stages_;
    PipelineContext ctx_;   ///< Reused per packet to avoid repeated construction
};

} // namespace nids
