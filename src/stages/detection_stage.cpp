#include "detection_stage.h"
#include "../core/logger.h"
#include "net_headers.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <arpa/inet.h>
#include <algorithm>

namespace nids {

// Helper functions
static uint32_t parse_ip(const std::string& s) {
    if (s == "any") return 0;
    uint32_t ip;
    if (inet_pton(AF_INET, s.c_str(), &ip) == 1) return ip;
    return 0; 
}

static uint16_t parse_port(const std::string& s) {
    if (s == "any") return 0;
    try { return static_cast<uint16_t>(std::stoi(s)); } catch (...) { return 0; }
}

static std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t");
    return s.substr(start, end - start + 1);
}

bool DetectionStage::load_rules(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return false;

    rules_.clear();
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        // Parse: alert <proto> <src> <sport> -> <dst> <dport> (<options>)
        std::stringstream ss(line);
        std::string action, proto_str, src_str, sport_str, arrow, dst_str, dport_str;
        
        ss >> action >> proto_str >> src_str >> sport_str >> arrow >> dst_str >> dport_str;
        if (action != "alert") continue;

        DdosRule rule;
        
        if (proto_str == "tcp") rule.proto = IPPROTO_TCP;
        else if (proto_str == "udp") rule.proto = IPPROTO_UDP;
        else if (proto_str == "icmp") rule.proto = IPPROTO_ICMP;
        
        rule.src_ip = parse_ip(src_str);
        rule.src_port = parse_port(sport_str);
        rule.dst_ip = parse_ip(dst_str);
        rule.dst_port = parse_port(dport_str);

        // Options
        size_t open_paren = line.find('(');
        size_t close_paren = line.rfind(')');
        if (open_paren == std::string::npos || close_paren == std::string::npos) continue;

        std::string opts_content = line.substr(open_paren + 1, close_paren - open_paren - 1);
        std::stringstream oss(opts_content);
        std::string token;
        bool has_threshold = false;

        // Naive split by ';'
        while(std::getline(oss, token, ';')) {
            token = trim(token);
            if (token.empty()) continue;

            if (token.find("msg:") == 0) {
                // msg:"..."
                size_t q1 = token.find('"');
                size_t q2 = token.rfind('"');
                if (q1 != std::string::npos && q2 > q1) {
                    rule.msg = token.substr(q1 + 1, q2 - q1 - 1);
                }
            } else if (token.find("sid:") == 0) {
                 try { rule.sid = std::stoi(token.substr(4)); } catch(...) {}
            } else if (token.find("threshold:") == 0) {
                // threshold: type limit, track by_src, count 100, seconds 60
                has_threshold = true;
                std::string t_body = token.substr(10);
                std::stringstream tss(t_body);
                std::string t_tok;
                while (std::getline(tss, t_tok, ',')) {
                    t_tok = trim(t_tok);
                    if (t_tok.find("count") == 0) {
                         try { rule.limit_count = std::stoi(t_tok.substr(6)); } catch(...) {} // "count "
                    } else if (t_tok.find("seconds") == 0) {
                         try { rule.limit_seconds = std::stoi(t_tok.substr(8)); } catch(...) {} // "seconds "
                    } else if (t_tok.find("track") == 0) {
                        if (t_tok.find("by_dst") != std::string::npos) rule.track = TrackType::BY_DST;
                    }
                }
            }
        }

        if (has_threshold) {
             rules_.push_back(rule);
             LOG_INFO("detection", "Loaded DDoS rule sid:%d msg:'%s' limit:%d/%ds", rule.sid, rule.msg.c_str(), rule.limit_count, rule.limit_seconds);
        }
    }
    return true;
}

bool DetectionStage::process(PipelineContext& ctx) {
    PacketSlot* pkt = ctx.packet;

    // Current time
    using namespace std::chrono;
    uint64_t now_ns = static_cast<uint64_t>(
        duration_cast<nanoseconds>(
            steady_clock::now().time_since_epoch()).count());

    // 1. Legacy global 5-tuple check
    if (pkt_threshold_ > 0) {
        auto& entry = flow_table_[pkt->flow_hash];
        uint64_t window_ns_global = static_cast<uint64_t>(window_ms_) * 1'000'000ULL;

        if (entry.window_start_ns == 0 || (now_ns - entry.window_start_ns) >= window_ns_global) {
            entry.window_start_ns = now_ns;
            entry.pkt_count       = 0;
            entry.byte_count      = 0;
            entry.alerted         = false;
        }

        entry.pkt_count++;
        entry.byte_count += pkt->length;
        ctx.flow_entry = &entry;

        if (entry.pkt_count >= pkt_threshold_ && !entry.alerted) {
             entry.alerted = true;
             ctx.alert = true;
             if (ctx.matched_count < PipelineContext::MAX_RULES) {
                 ctx.matched_rules[ctx.matched_count++] = -1; 
             }
             LOG_WARN("detection", "Global DDoS ALERT flow=0x%08X rate=%u", pkt->flow_hash, entry.pkt_count);
        }
    }

    // 2. Rulechecks
    if (rules_.empty()) return true;

    if (pkt->net_offset == 0 || pkt->net_offset + sizeof(Ipv4Header) > pkt->length) return true;

    const auto* ip_hdr = reinterpret_cast<const Ipv4Header*>(pkt->data + pkt->net_offset);
    uint32_t src = ip_hdr->src;
    uint32_t dst = ip_hdr->dst;
    uint8_t  proto = ip_hdr->protocol;
    uint16_t sport = 0;
    uint16_t dport = 0;

    if (pkt->transport_offset > 0 && static_cast<uint32_t>(pkt->transport_offset) + 4 <= pkt->length) {
        const uint8_t* t_ptr = pkt->data + pkt->transport_offset;
        sport = ntohs(*reinterpret_cast<const uint16_t*>(t_ptr));
        dport = ntohs(*reinterpret_cast<const uint16_t*>(t_ptr + 2));
    }
    
    for (const auto& rule : rules_) {
        // Filter Match
        if (rule.proto != 0 && rule.proto != proto) continue;
        if (rule.src_ip != 0 && rule.src_ip != src) continue;
        if (rule.dst_ip != 0 && rule.dst_ip != dst) continue;
        if (rule.src_port != 0 && rule.src_port != sport) continue;
        if (rule.dst_port != 0 && rule.dst_port != dport) continue;

        // Construct Key
        std::string key;
        char ip_buf[INET_ADDRSTRLEN];
        if (rule.track == TrackType::BY_SRC) {
             inet_ntop(AF_INET, &src, ip_buf, sizeof(ip_buf));
             key = std::to_string(rule.sid) + ":S:" + std::string(ip_buf);
        } else {
             inet_ntop(AF_INET, &dst, ip_buf, sizeof(ip_buf));
             key = std::to_string(rule.sid) + ":D:" + std::string(ip_buf);
        }

        auto& st = rule_states_[key];
        uint64_t rule_window_ns = (uint64_t)rule.limit_seconds * 1'000'000'000ULL;

        if (st.window_start_ns == 0 || (now_ns - st.window_start_ns) >= rule_window_ns) {
            st.window_start_ns = now_ns;
            st.pkt_count = 0;
            st.alerted = false;
        }
        
        st.pkt_count++;
        
        if (st.pkt_count >= rule.limit_count && !st.alerted) {
             st.alerted = true;
             ctx.alert = true;
             if (ctx.matched_count < PipelineContext::MAX_RULES) {
                 ctx.matched_rules[ctx.matched_count++] = rule.sid;
             }
             LOG_WARN("detection", "Rule DDoS ALERT sid=%d msg='%s' rate=%u", rule.sid, rule.msg.c_str(), st.pkt_count);
        }
    }

    return true;  // Always continue — detection is non-blocking
}

} // namespace nids
