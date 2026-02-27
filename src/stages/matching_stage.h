#pragma once
#include "../core/stage.h"
#include <vector>
#include <string>
#include <unordered_map>

namespace nids {

/**
 * @brief Simplified rule in Snort-like format.
 *
 * Supported fields:
 *   id       — unique integer rule identifier
 *   message  — alert message
 *   content  — byte pattern to search in the payload (exact match)
 *   proto    — IPPROTO_TCP, IPPROTO_UDP or 0 for any
 *   dst_port — destination port or 0 for any
 */
struct MatchRule {
    int         id       = 0;
    std::string message;
    std::string content;     ///< Raw bytes to search (empty = match all)
    uint8_t     proto    = 0;
    uint16_t    dst_port = 0;
};

/**
 * @brief MatchingStage — simple multi-pattern payload scanner.
 *
 * For each packet, iterates compiled rules and checks:
 *   1. Protocol filter
 *   2. Destination port filter
 *   3. Content (Boyer-Moore-Horspool substring search)
 *
 * In production this would be replaced by a Hyperscan or Snort3
 * integration. The interface (loadRules / hot_update) remains the same.
 */
class MatchingStage : public IStage {
public:
    bool init()                        override { return true; }
    bool process(PipelineContext& ctx)  override;
    std::string name() const           override { return "Matching"; }

    /** @brief Load rules from a simple text file. */
    bool load_rules(const std::string& path);

    /** @brief Add / replace a rule at runtime (called by CommThread). */
    void add_rule(MatchRule rule);

    const std::vector<MatchRule>& rules() const { return rules_; }

private:
    std::vector<MatchRule> rules_;

    /** @brief Boyer-Moore-Horspool search returning true if `pat` found in `text`. */
    static bool bmh_search(const uint8_t* text, size_t text_len,
                           const uint8_t* pat,  size_t pat_len) noexcept;
};

} // namespace nids
