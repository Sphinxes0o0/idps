#pragma once
#include <cstdint>
#include <string>
#include <array>

namespace nids {

/**
 * @brief Represents a detected security event that will be
 * aggregated and dispatched by the Communication Thread.
 */
struct SecEvent {
    enum class Type : uint8_t {
        UNKNOWN    = 0,
        DDOS       = 1,   ///< DDoS threshold exceeded
        RULE_MATCH = 2,   ///< Snort-like rule matched
    };

    Type     type        = Type::UNKNOWN;
    uint64_t timestamp   = 0;   ///< Nanoseconds since epoch

    // Network 5-tuple
    uint32_t src_ip      = 0;
    uint32_t dst_ip      = 0;
    uint16_t src_port    = 0;
    uint16_t dst_port    = 0;
    uint8_t  ip_proto    = 0;

    // Match context
    int      rule_id     = -1;   ///< Matched rule ID (-1 = N/A)
    char     message[96] = {};   ///< Short description

    void set_message(const char* msg) noexcept {
        std::snprintf(message, sizeof(message), "%s", msg);
    }

    /** @brief Serialize to JSON string (simple, no dependency). */
    std::string to_json() const;
};

} // namespace nids
