#include "event_stage.h"
#include "net_headers.h"
#include "../core/logger.h"
#include <arpa/inet.h>
#include <netinet/in.h>  // IPPROTO_TCP / UDP
#include <cstring>

namespace nids {

bool EventStage::process(PipelineContext& ctx) {
    if (!ctx.alert) return true;  // Nothing to report

    PacketSlot* pkt = ctx.packet;
    SecEvent    ev;

    ev.timestamp = pkt->timestamp;

    // Extract IP 5-tuple from decoded header
    if (pkt->net_offset > 0 && pkt->length >= pkt->net_offset + sizeof(Ipv4Header)) {
        const auto* ip = reinterpret_cast<const Ipv4Header*>(
            pkt->data + pkt->net_offset);
        ev.src_ip   = ntohl(ip->src);
        ev.dst_ip   = ntohl(ip->dst);
        ev.ip_proto = ip->protocol;
    }

    if (pkt->transport_offset > 0 && pkt->transport_offset < pkt->payload_offset) {
        const uint8_t* th = pkt->data + pkt->transport_offset;
        // Both TCP & UDP: src_port @ 0..1, dst_port @ 2..3 (network order)
        // Manual big-endian assembly already gives host byte order
        ev.src_port = static_cast<uint16_t>((th[0] << 8) | th[1]);
        ev.dst_port = static_cast<uint16_t>((th[2] << 8) | th[3]);
    }

    // Determine event type and message
    if (ctx.matched_count > 0 && ctx.matched_rules[0] == -1) {
        ev.type    = SecEvent::Type::DDOS;
        ev.rule_id = -1;
        ev.set_message("DDoS threshold exceeded");
    } else if (ctx.matched_count > 0) {
        ev.type    = SecEvent::Type::RULE_MATCH;
        ev.rule_id = ctx.matched_rules[0];
        ev.set_message("Snort rule match");
    }

    LOG_INFO("event",
             "%-10s rule_id=%-3d src=%u.%u.%u.%u:%-5u dst=%u.%u.%u.%u:%-5u proto=%u",
             ev.type == SecEvent::Type::DDOS ? "DDOS" : "RULE_MATCH",
             ev.rule_id,
             (ev.src_ip >> 24) & 0xFF, (ev.src_ip >> 16) & 0xFF,
             (ev.src_ip >>  8) & 0xFF,  ev.src_ip        & 0xFF, ev.src_port,
             (ev.dst_ip >> 24) & 0xFF, (ev.dst_ip >> 16) & 0xFF,
             (ev.dst_ip >>  8) & 0xFF,  ev.dst_ip        & 0xFF, ev.dst_port,
             ev.ip_proto);
    event_queue_->push(ev);
    return true;
}

} // namespace nids
