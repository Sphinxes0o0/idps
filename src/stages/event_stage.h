#pragma once
#include "../core/stage.h"
#include "../ipc/event_queue.hpp"
#include <memory>

namespace nids {

/**
 * @brief EventStage — convert pipeline alerts into SecEvent objects.
 *
 * Runs at the end of the pipeline. If ctx.alert is set (by DetectionStage
 * or MatchingStage), it formats a SecEvent from the decoded packet fields
 * and pushes it onto the shared EventQueue.
 *
 * The EventQueue is drained by the Communication Thread.
 */
class EventStage : public IStage {
public:
    explicit EventStage(std::shared_ptr<EventQueue> queue)
        : event_queue_(std::move(queue)) {}

    bool init()                        override { return event_queue_ != nullptr; }
    bool process(PipelineContext& ctx)  override;
    std::string name() const           override { return "EventGen"; }

private:
    std::shared_ptr<EventQueue> event_queue_;
};

} // namespace nids
