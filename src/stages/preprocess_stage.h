#pragma once
#include "../core/stage.h"

namespace nids {

/**
 * @brief PreprocessStage — first gate in the pipeline.
 *
 * Responsibilities:
 *   - Reject obviously malformed packets (too short, too long).
 *   - Sanity-check minimum Ethernet frame length (14 bytes header).
 *   - Early drop: sets ctx.drop = true so downstream stages are skipped.
 */
class PreprocessStage : public IStage {
public:
    static constexpr uint32_t MIN_FRAME = 14;    ///< Minimum Ethernet header
    static constexpr uint32_t MAX_FRAME = 65535; ///< Jumbo safety ceiling

    bool init()                       override { return true; }
    bool process(PipelineContext& ctx) override;
    std::string name() const          override { return "Preprocess"; }
};

} // namespace nids
