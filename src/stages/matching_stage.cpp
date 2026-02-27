#include "matching_stage.h"
#include "../core/logger.h"
#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>

namespace nids {

// ---- Boyer-Moore-Horspool ---------------------------------------------------

bool MatchingStage::bmh_search(const uint8_t* text, size_t tlen,
                                const uint8_t* pat,  size_t plen) noexcept {
    if (plen == 0) return true;
    if (plen > tlen) return false;

    // Build bad-character skip table
    size_t skip[256];
    std::fill(skip, skip + 256, plen);
    for (size_t i = 0; i + 1 < plen; ++i)
        skip[pat[i]] = plen - 1 - i;

    size_t pos = 0;
    while (pos <= tlen - plen) {
        size_t j = plen - 1;
        while (j < plen && text[pos + j] == pat[j]) {
            if (j == 0) return true;
            --j;
        }
        pos += skip[text[pos + plen - 1]];
    }
    return false;
}

// ---- Rule file format -------------------------------------------------------
// One rule per line:
//   <id> <proto> <dst_port> "<content>" <message>
// Example:
//   1 6 80 "GET /evil" "HTTP exploit attempt"
// proto: 6=TCP, 17=UDP, 0=any
// dst_port: 0=any

bool MatchingStage::load_rules(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    rules_.clear();
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        MatchRule r;
        int proto_int = 0, port_int = 0;
        if (!(iss >> r.id >> proto_int >> port_int)) continue;
        r.proto    = static_cast<uint8_t>(proto_int);
        r.dst_port = static_cast<uint16_t>(port_int);

        // Parse quoted content
        std::string token;
        if (iss >> std::ws && iss.peek() == '"') {
            iss.get();  // consume '"'
            std::getline(iss, r.content, '"');
        }

        // Remainder is message
        iss >> std::ws;
        if (iss.peek() == '"') {
            iss.get();
            std::getline(iss, r.message, '"');
        } else {
            std::getline(iss, r.message);
        }

        LOG_DEBUG("matching", "loaded rule id=%d proto=%u port=%u content='%s' msg='%s'",
                  r.id, r.proto, r.dst_port, r.content.c_str(), r.message.c_str());
        rules_.push_back(std::move(r));
    }
    LOG_INFO("matching", "loaded %zu rule(s) from '%s'", rules_.size(), path.c_str());
    return true;
}

void MatchingStage::add_rule(MatchRule rule) {
    // Replace existing rule with same ID if present
    for (auto& r : rules_) {
        if (r.id == rule.id) { r = std::move(rule); return; }
    }
    rules_.push_back(std::move(rule));
}

// ---- Per-packet matching ----------------------------------------------------

bool MatchingStage::process(PipelineContext& ctx) {
    if (rules_.empty()) return true;

    PacketSlot* pkt = ctx.packet;
    uint16_t poff = pkt->payload_offset;
    if (poff >= pkt->length) return true;  // No payload

    const uint8_t* payload  = pkt->data + poff;
    size_t         pay_len  = pkt->length - poff;
    uint8_t        proto    = pkt->ip_proto;

    // Reconstruct dst_port from decoded transport header
    uint16_t dst_port = 0;
    if (pkt->transport_offset < pkt->payload_offset && pkt->transport_offset > 0) {
        const uint8_t* th = pkt->data + pkt->transport_offset;
        // Both TCP and UDP have dst_port at bytes [2..3]
        // Manual big-endian assembly already gives host byte order
        dst_port = static_cast<uint16_t>(
            (static_cast<uint16_t>(th[2]) << 8) | th[3]);
    }

    for (const auto& rule : rules_) {
        // Proto filter
        if (rule.proto != 0 && rule.proto != proto) continue;
        // Port filter
        if (rule.dst_port != 0 && rule.dst_port != dst_port) continue;
        // Content match
        if (!rule.content.empty()) {
            const auto* pat = reinterpret_cast<const uint8_t*>(rule.content.data());
            if (!bmh_search(payload, pay_len, pat, rule.content.size()))
                continue;
        }

        // Matched
        LOG_INFO("matching",
                 "rule #%d matched: proto=%u dst_port=%u content='%s' | %s",
                 rule.id, proto, dst_port,
                 rule.content.empty() ? "(any)" : rule.content.c_str(),
                 rule.message.c_str());
        ctx.alert = true;
        if (ctx.matched_count < PipelineContext::MAX_RULES) {
            ctx.matched_rules[ctx.matched_count++] = rule.id;
        }
    }

    return true;  // Continue even if matched
}

} // namespace nids
