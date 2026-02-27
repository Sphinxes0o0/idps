#include "decode_stage.h"
#include "net_headers.h"
#include "../core/logger.h"
#include <netinet/in.h>  // IPPROTO_TCP, IPPROTO_UDP
#include <arpa/inet.h>

namespace {
// Format host-order uint32_t IP to "a.b.c.d" string
static std::string fmt_ip(uint32_t ip_host) {
    char buf[INET_ADDRSTRLEN];
    uint32_t nip = htonl(ip_host);
    inet_ntop(AF_INET, &nip, buf, sizeof(buf));
    return buf;
}
} // anonymous namespace

namespace nids {

// FNV-1a hash for 5-tuple (fast, good distribution)
static uint32_t fnv1a_5tuple(uint32_t sip, uint32_t dip,
                              uint16_t sp,  uint16_t dp,
                              uint8_t  proto) noexcept {
    uint32_t h = 2166136261u;
    auto mix = [&](uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            h ^= (v & 0xFF);
            h *= 16777619u;
            v >>= 8;
        }
    };
    mix(sip); mix(dip);
    h ^= sp;  h *= 16777619u;
    h ^= dp;  h *= 16777619u;
    h ^= proto; h *= 16777619u;
    return h;
}

bool DecodeStage::process(PipelineContext& ctx) {
    PacketSlot* pkt = ctx.packet;
    const uint8_t* buf = pkt->data;
    uint32_t len = pkt->length;

    // ---- Ethernet layer -----------------------------------------------------
    if (len < sizeof(EthHeader)) { ctx.drop = true; return false; }
    const auto* eth = reinterpret_cast<const EthHeader*>(buf);

    uint16_t offset = sizeof(EthHeader);
    uint16_t ether_type = ntohs(eth->type);
    pkt->eth_offset = 0;

    // Strip VLAN 802.1Q tag (0x8100) — one level only
    if (ether_type == ETHERTYPE_VLAN && len >= static_cast<uint32_t>(offset + 4)) {
        offset += 4;
        ether_type = ntohs(*reinterpret_cast<const uint16_t*>(buf + offset - 2));
    }

    // We only process IPv4 for now; drop everything else (IPv6 TODO)
    if (ether_type != ETHERTYPE_IPV4) {
        LOG_DEBUG("decode", "non-IPv4 ethertype=0x%04X — dropped", ether_type);
        ctx.drop = true;
        return false;
    }

    // ---- IPv4 layer ---------------------------------------------------------
    if (len < offset + sizeof(Ipv4Header)) { ctx.drop = true; return false; }
    const auto* ip = reinterpret_cast<const Ipv4Header*>(buf + offset);

    if (ip->version() != 4) {
        LOG_DEBUG("decode", "bad IP version %u — dropped", ip->version());
        ctx.drop = true; return false;
    }
    uint16_t ip_hdr_len = ip->ihl();
    if (ip_hdr_len < 20 || len < offset + ip_hdr_len) {
        LOG_DEBUG("decode", "malformed IPv4 header (ihl=%u len=%u) — dropped", ip_hdr_len, len);
        ctx.drop = true; return false;
    }

    // Ignore IP fragments (reassembly not implemented)
    if (ip->is_fragment()) {
        LOG_DEBUG("decode", "IP fragment — dropped");
        ctx.drop = true; return false;
    }

    pkt->net_offset = offset;
    pkt->ip_proto   = ip->protocol;

    uint32_t src_ip = ntohl(ip->src);
    uint32_t dst_ip = ntohl(ip->dst);
    uint16_t src_port = 0, dst_port = 0;

    offset += ip_hdr_len;

    // ---- Transport layer ----------------------------------------------------
    if (ip->protocol == IPPROTO_TCP) {
        if (len < offset + sizeof(TcpHeader)) { ctx.drop = true; return false; }
        const auto* tcp = reinterpret_cast<const TcpHeader*>(buf + offset);
        src_port = tcp->sport();
        dst_port = tcp->dport();
        pkt->transport_offset = offset;
        pkt->payload_offset   = static_cast<uint16_t>(offset + tcp->hdr_len());

    } else if (ip->protocol == IPPROTO_UDP) {
        if (len < offset + sizeof(UdpHeader)) { ctx.drop = true; return false; }
        const auto* udp = reinterpret_cast<const UdpHeader*>(buf + offset);
        src_port = udp->sport();
        dst_port = udp->dport();
        pkt->transport_offset = offset;
        pkt->payload_offset   = static_cast<uint16_t>(offset + sizeof(UdpHeader));

    } else {
        // ICMP or other — no port, just pass through
        pkt->transport_offset = offset;
        pkt->payload_offset   = offset;
    }

    // ---- Flow hash ----------------------------------------------------------
    pkt->flow_hash = fnv1a_5tuple(src_ip, dst_ip, src_port, dst_port, ip->protocol);

    LOG_TRACE("decode",
              "proto=%u src=%s:%u dst=%s:%u len=%u payload_offset=%u hash=0x%08X",
              ip->protocol,
              fmt_ip(src_ip).c_str(), src_port,
              fmt_ip(dst_ip).c_str(), dst_port,
              pkt->length, pkt->payload_offset,
              pkt->flow_hash);

    return true;
}

} // namespace nids
