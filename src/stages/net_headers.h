#pragma once
#include <cstdint>
#include <arpa/inet.h>

namespace nids {

// ---- Ethernet ---------------------------------------------------------------
#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;  // network byte order
};

// ---- IPv4 -------------------------------------------------------------------
struct Ipv4Header {
    uint8_t  ihl_ver;         // version (4 bits) + IHL (4 bits)
    uint8_t  tos;
    uint16_t total_len;       // network byte order
    uint16_t id;
    uint16_t frag_off;        // flags + fragment offset
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;

    uint8_t  version() const { return ihl_ver >> 4; }
    uint8_t  ihl()     const { return (ihl_ver & 0x0F) << 2; }  // in bytes
    uint16_t len()     const { return ntohs(total_len); }
    bool     is_fragment() const {
        return (ntohs(frag_off) & 0x1FFF) != 0 ||    // fragment offset != 0
               (ntohs(frag_off) & 0x2000) != 0;      // More Fragments bit
    }
};

// ---- TCP --------------------------------------------------------------------
struct TcpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off;  // data offset (4 bits, upper)
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;

    uint8_t  hdr_len()  const { return (data_off >> 4) << 2; }  // bytes
    uint16_t sport()    const { return ntohs(src_port); }
    uint16_t dport()    const { return ntohs(dst_port); }
};

// ---- UDP --------------------------------------------------------------------
struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;

    uint16_t sport() const { return ntohs(src_port); }
    uint16_t dport() const { return ntohs(dst_port); }
};
#pragma pack(pop)

// EtherType constants
static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
static constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
static constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
static constexpr uint16_t ETHERTYPE_VLAN = 0x8100;

} // namespace nids
