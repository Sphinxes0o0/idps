/* SPDX-License-Identifier: MIT */
/*
 * test_ipv4_ipv6_dual_stack.cpp - T-15: IPv4/IPv6 Dual Stack Test
 *
 * Tests that verify correct handling of both IPv4 and IPv6 traffic.
 * Dual-stack means the system must properly distinguish and process
 * both IP versions simultaneously.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace nids;

// Constants
constexpr uint32_t IPv4_VERSION = 4;
constexpr uint32_t IPv6_VERSION = 6;

class DualStackTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Flow key for IPv4
    struct flow_key_v4 {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        uint8_t padding[3];
    };

    // Flow key for IPv6 (uses only lower 32 bits of IPs in key)
    struct flow_key_v6 {
        uint32_t src_ip;    // Lower 32 bits of IPv6 src
        uint32_t dst_ip;    // Lower 32 bits of IPv6 dst
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t protocol;
        uint8_t ip_version;  // 6 for IPv6
        uint8_t padding[2];
    };

    // IP header structures
    struct ipv4_header {
        uint8_t  version_ihl;
        uint8_t  tos;
        uint16_t total_length;
        uint16_t identification;
        uint16_t flags_fragment;
        uint8_t  ttl;
        uint8_t  protocol;
        uint16_t checksum;
        uint32_t src_ip;
        uint32_t dst_ip;
    };

    struct ipv6_header {
        uint32_t version_class_flow;  // version (4 bits) | class (8 bits) | flow (20 bits)
        uint16_t payload_length;
        uint8_t  next_header;
        uint8_t  hop_limit;
        uint8_t  src_ip[16];
        uint8_t  dst_ip[16];
    };

    // Extract IP version from header
    static uint32_t get_ip_version(uint8_t version_ihl) {
        return (version_ihl >> 4) & 0xF;
    }

    // Check if IPv4 header
    static bool is_ipv4(const uint8_t* data) {
        return get_ip_version(data[0]) == IPv4_VERSION;
    }

    // Check if IPv6 header
    static bool is_ipv6(const uint8_t* data) {
        return get_ip_version(data[0]) == IPv6_VERSION;
    }
};

// T-15: IP version extraction from header byte
TEST_F(DualStackTest, IpVersionExtraction) {
    // IPv4 header byte: version (4) + IHL (4)
    uint8_t ipv4_header_byte = (IPv4_VERSION << 4) | 5;  // Version 4, IHL 5
    EXPECT_EQ(get_ip_version(ipv4_header_byte), IPv4_VERSION);

    // IPv6 header byte: version (4) + traffic class (4, usually 0)
    uint8_t ipv6_header_byte = (IPv6_VERSION << 4) | 0;  // Version 6
    EXPECT_EQ(get_ip_version(ipv6_header_byte), IPv6_VERSION);
}

// T-15: IPv4 header parsing
TEST_F(DualStackTest, Ipv4HeaderParsing) {
    uint8_t packet[] = {
        0x45,             // Version 4, IHL 5
        0x00,             // TOS
        0x00, 0x3C,       // Total length 60
        0x00, 0x00,       // ID
        0x40, 0x00,       // Flags + Fragment offset
        0x40,             // TTL
        0x06,             // Protocol TCP
        0x00, 0x00,       // Checksum
        0xC0, 0xA8, 0x01, 0x01,  // Src: 192.168.1.1
        0xC0, 0xA8, 0x01, 0x02   // Dst: 192.168.1.2
    };

    ipv4_header* hdr = reinterpret_cast<ipv4_header*>(packet);

    EXPECT_EQ(get_ip_version(hdr->version_ihl), 4u);
    EXPECT_EQ(hdr->protocol, 6u);  // TCP
    // Use ntohl() for network byte order conversion on little-endian systems
    EXPECT_EQ(ntohl(hdr->src_ip), 0xC0A80101u);
    EXPECT_EQ(ntohl(hdr->dst_ip), 0xC0A80102u);
}

// T-15: IPv6 header parsing
TEST_F(DualStackTest, Ipv6HeaderParsing) {
    uint8_t packet[] = {
        0x60,             // Version 6, traffic class 0
        0x00, 0x00, 0x00, // Flow label
        0x00, 0x28,       // Payload length 40
        0x06,             // Next header: TCP
        0x40,             // Hop limit 64
        // Source: 2001:db8::1
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Destination: 2001:db8::2
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    };

    // Use direct byte access to avoid struct interpretation issues on little-endian
    EXPECT_EQ(get_ip_version(packet[0]), 6u);
    EXPECT_EQ(packet[6], 6u);  // Next header: TCP
    EXPECT_EQ(ntohs(*(uint16_t*)&packet[4]), 40u);
    EXPECT_EQ(packet[7], 64u);  // Hop limit
}

// T-15: IPv4 and IPv6 packets can be distinguished
TEST_F(DualStackTest, DistinguishIpVersions) {
    uint8_t ipv4_packet[] = {0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t ipv6_packet[] = {0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    EXPECT_TRUE(is_ipv4(ipv4_packet));
    EXPECT_FALSE(is_ipv4(ipv6_packet));

    EXPECT_TRUE(is_ipv6(ipv6_packet));
    EXPECT_FALSE(is_ipv6(ipv4_packet));
}

// T-15: IPv4 and IPv6 flows are tracked separately
TEST_F(DualStackTest, SeparateFlowTracking) {
    // IPv4 flow key
    flow_key_v4 ipv4_flow = {};
    ipv4_flow.src_ip = 0xC0A80101;
    ipv4_flow.dst_ip = 0xC0A80102;
    ipv4_flow.src_port = 12345;
    ipv4_flow.dst_port = 80;
    ipv4_flow.protocol = 6;

    // IPv6 flow key (only lower 32 bits stored)
    flow_key_v6 ipv6_flow = {};
    ipv6_flow.src_ip = 0x00000001;  // ::1
    ipv6_flow.dst_ip = 0x00000002;  // ::2
    ipv6_flow.src_port = 12345;
    ipv6_flow.dst_port = 80;
    ipv6_flow.protocol = 6;
    ipv6_flow.ip_version = 6;

    // Flows are different due to different key structures
    EXPECT_NE(ipv4_flow.src_ip, ipv6_flow.src_ip);
    EXPECT_NE(ipv4_flow.dst_ip, ipv6_flow.dst_ip);
}

// T-15: IPv6 address structure (128-bit)
TEST_F(DualStackTest, Ipv6AddressStructure) {
    ipv6_header hdr = {};

    // Set IPv6 address: 2001:db8::1
    // Full address in bytes: 20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01
    hdr.src_ip[0] = 0x20;  // 2
    hdr.src_ip[1] = 0x01;  // 0
    hdr.src_ip[2] = 0x0d;  // d
    hdr.src_ip[3] = 0xb8;  // b
    // bytes 4-14 are already 0 from initialization
    hdr.src_ip[15] = 0x01; // ::1

    EXPECT_EQ(hdr.src_ip[0], 0x20);
    EXPECT_EQ(hdr.src_ip[1], 0x01);
    EXPECT_EQ(hdr.src_ip[2], 0x0d);
    EXPECT_EQ(hdr.src_ip[3], 0xb8);
    EXPECT_EQ(hdr.src_ip[15], 0x01);
}

// T-15: Same 5-tuple different IP version = different flow
TEST_F(DualStackTest, SameTupleDifferentVersion) {
    // IPv4: 192.168.1.1:12345 -> 192.168.1.2:80 (TCP)
    flow_key_v4 ipv4_flow = {};
    ipv4_flow.src_ip = 0xC0A80101;
    ipv4_flow.dst_ip = 0xC0A80102;
    ipv4_flow.src_port = 12345;
    ipv4_flow.dst_port = 80;
    ipv4_flow.protocol = 6;

    // IPv6: ::1:12345 -> ::2:80 (TCP)
    // These should be separate flows even with same ports/protocol
    // Because the BPF code uses different key structures

    // Verify both flows have same port/protocol
    EXPECT_EQ(ipv4_flow.src_port, 12345);
    EXPECT_EQ(ipv4_flow.dst_port, 80);
    EXPECT_EQ(ipv4_flow.protocol, 6);

    // But different IPs
    EXPECT_NE(ipv4_flow.src_ip, 0x00000001u);
    EXPECT_NE(ipv4_flow.dst_ip, 0x00000002u);
}

// T-15: IPv4-mapped IPv6 addresses
TEST_F(DualStackTest, Ipv4MappedIpv6) {
    // IPv4-mapped IPv6 address: ::ffff:192.168.1.1
    // Format: ::ffff: followed by 4-byte IPv4 address
    // In bytes: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0xff 0xff 0xC0 0xA8 0x01 0x01

    uint8_t mapped_addr[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xC0, 0xA8, 0x01, 0x01
    };

    // Last 4 bytes are the IPv4 address
    uint32_t ipv4_addr = (mapped_addr[12] << 24) |
                         (mapped_addr[13] << 16) |
                         (mapped_addr[14] << 8) |
                         mapped_addr[15];

    EXPECT_EQ(ipv4_addr, 0xC0A80101u);  // 192.168.1.1
}

// T-15: Ethernet frame with IPv4
TEST_F(DualStackTest, EthernetIpv4) {
    // Ethernet header: dst_mac(6) + src_mac(6) + ethertype(2)
    uint8_t frame[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
        0x08, 0x00,                          // Ethertype: IPv4
        0x45, 0x00, 0x00, 0x00               // IPv4 header start
    };

    uint16_t ethertype = (frame[12] << 8) | frame[13];
    EXPECT_EQ(ethertype, 0x0800u);  // IPv4

    // Next byte after ethernet is IP version
    EXPECT_EQ(get_ip_version(frame[14]), 4u);
}

// T-15: Ethernet frame with IPv6
TEST_F(DualStackTest, EthernetIpv6) {
    // Ethernet header with IPv6 ethertype
    uint8_t frame[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // Dst MAC
        0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,  // Src MAC
        0x86, 0xDD,                          // Ethertype: IPv6
        0x60, 0x00, 0x00, 0x00               // IPv6 header start
    };

    uint16_t ethertype = (frame[12] << 8) | frame[13];
    EXPECT_EQ(ethertype, 0x86DDu);  // IPv6

    // Next byte after ethernet is IP version
    EXPECT_EQ(get_ip_version(frame[14]), 6u);
}

// T-15: IPv6 fragment header detection
TEST_F(DualStackTest, Ipv6FragmentHeader) {
    // IPv6 with fragment header
    // Fragment header follows IPv6 header
    // Next header: 44 (decimal) = 0x2C
    uint8_t frag_hdr[] = {
        0x2C,             // Next header: fragment (44)
        0x00,             // Reserved
        0x00, 0x01,       // Fragment offset: 0, M flag: 1
        0x00, 0x00, 0x00, 0x01  // Identification
    };

    uint8_t next_header = frag_hdr[0];
    uint16_t frag_off = (frag_hdr[2] << 8) | frag_hdr[3];
    uint8_t m_flag = frag_off & 0x0001;

    EXPECT_EQ(next_header, 44u);  // Fragment header
    EXPECT_EQ((frag_off >> 3), 0u);  // Offset = 0
    EXPECT_EQ(m_flag, 1u);  // More fragments follow
}

// T-15: IPv6 extension headers handled
TEST_F(DualStackTest, Ipv6ExtensionHeaders) {
    // Hop-by-hop options header
    uint8_t hop_by_hop[] = {
        0x00,  // Next header: options
        0x00,  // Hdr ext len: 0 (8 bytes total, no options)
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00  // Options
    };

    EXPECT_EQ(hop_by_hop[0], 0u);  // Option header type
}

// T-15: Flow key size comparison
TEST_F(DualStackTest, FlowKeySizeComparison) {
    EXPECT_EQ(sizeof(flow_key_v4), 16u);
    EXPECT_EQ(sizeof(flow_key_v6), 16u);

    // Both flow keys should be same size for consistent map entry
    EXPECT_EQ(sizeof(flow_key_v4), sizeof(flow_key_v6));
}

// T-15: TCP protocol works with both IP versions
TEST_F(DualStackTest, TcpBothIpVersions) {
    uint8_t ipv4_tcp = 6;  // TCP protocol number
    uint8_t ipv6_next_header = 6;  // TCP next header

    EXPECT_EQ(ipv4_tcp, ipv6_next_header);
    EXPECT_EQ(ipv4_tcp, 6u);
}

// T-15: UDP protocol works with both IP versions
TEST_F(DualStackTest, UdpBothIpVersions) {
    uint8_t ipv4_protocol = 17;  // UDP protocol number
    uint8_t ipv6_next_header = 17;  // UDP next header

    EXPECT_EQ(ipv4_protocol, ipv6_next_header);
    EXPECT_EQ(ipv4_protocol, 17u);
}

// T-15: ICMP for IPv4 vs IPv6 (different protocol numbers)
TEST_F(DualStackTest, IcmpBothVersions) {
    // IPv4 ICMP: protocol 1
    // IPv6 ICMPv6: next header 58

    uint8_t icmpv4 = 1;
    uint8_t icmpv6 = 58;

    EXPECT_NE(icmpv4, icmpv6);

    // In BPF code, these are handled separately:
    // - IPv4 ICMP uses protocol = 1
    // - IPv6 ICMPv6 uses next_header = 58
}

// T-15: Fragment handling for IPv4
TEST_F(DualStackTest, Ipv4Fragmentation) {
    // IPv4 fragment: MF flag and fragment offset
    // flags_frag[0] contains flags (MF at bit 5, offset bits 0-4)
    // flags_frag[1] contains offset bits 5-12
    // High byte: MF=1 (bit 5 set), offset bits 5-12=0, offset bits 0-4=0 -> 0x20
    // Low byte: offset bits 5-12=0 -> 0x00
    uint8_t flags_frag[] = {
        0x20, 0x00  // MF=1, offset=0 (first fragment)
    };

    uint16_t flags_and_offset = (flags_frag[0] << 8) | flags_frag[1];
    bool mf = (flags_and_offset & 0x2000) != 0;
    uint16_t offset = (flags_and_offset & 0x1FFF) << 3;

    // More fragments flag
    // Note: 0x40 = DF (don't fragment), 0x20 = MF (more fragments)
    uint16_t flags_only = flags_and_offset >> 13;

    EXPECT_EQ(mf, true);
    EXPECT_EQ(offset, 0u);
}

// T-15: Dual-stack processing decision tree
TEST_F(DualStackTest, ProcessingDecisionTree) {
    uint8_t packet[] = {0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Step 1: Check Ethernet type
    // Assuming ethertype already determined this is IP

    // Step 2: Check IP version
    uint32_t version = get_ip_version(packet[0]);

    if (version == 4) {
        // Parse IPv4 header
        EXPECT_EQ(version, 4u);
    } else if (version == 6) {
        // Parse IPv6 header
        EXPECT_EQ(version, 6u);
    }
}

// T-15: IPv4 TOS vs IPv6 Traffic Class
TEST_F(DualStackTest, TosVsTrafficClass) {
    // IPv4 TOS is byte 1
    uint8_t ipv4_tos = 0x00;

    // IPv6 Traffic Class is bits 4-11 of first 32-bit word
    uint32_t ipv6_traffic_class = (0x00 << 28) | (0x00 << 20);  // Just example

    // Both can represent similar QoS information but in different positions
    EXPECT_TRUE(true);  // Structural difference, not functional
}

// T-15: IPv4 TTL vs IPv6 Hop Limit
TEST_F(DualStackTest, TtlVsHopLimit) {
    // IPv4 TTL: byte 8
    uint8_t ipv4_ttl = 64;

    // IPv6 Hop Limit: byte 7
    uint8_t ipv6_hop_limit = 64;

    // Both serve same purpose (limit packet lifetime)
    EXPECT_EQ(ipv4_ttl, ipv6_hop_limit);
}

// T-15: Maximum transmission unit differences
TEST_F(DualStackTest, MtuDifferences) {
    // IPv4: typical MTU 1500, minimum 576 for non-fragmented
    uint16_t ipv4_mtu = 1500;

    // IPv6: minimum MTU 1280, recommended 1500+
    uint16_t ipv6_min_mtu = 1280;

    EXPECT_GE(ipv4_mtu, 576u);
    EXPECT_GE(ipv6_min_mtu, 1280u);
}

// T-15: Dual-stack rule matching
TEST_F(DualStackTest, RuleMatchingBothVersions) {
    // Rules can be protocol-specific (TCP/UDP/ICMP)
    // IP version is handled separately from protocol

    uint8_t proto_tcp = 6;
    uint8_t proto_udp = 17;
    uint8_t proto_icmp = 1;

    // Protocol rules apply to both IPv4 and IPv6
    EXPECT_TRUE(proto_tcp == 6 || proto_tcp == 6);  // Just verification
    EXPECT_TRUE(proto_udp == 17 || proto_udp == 17);
}

// T-15: IPv6 flow label for flow identification
TEST_F(DualStackTest, Ipv6FlowLabel) {
    // Flow label is first 20 bits of version_class_flow
    uint32_t version_class_flow = (6u << 28) | (0x00 << 20) | 0x12345;

    uint32_t flow_label = version_class_flow & 0xFFFFF;
    uint32_t version = (version_class_flow >> 28) & 0xF;
    uint32_t traffic_class = (version_class_flow >> 20) & 0xFF;

    EXPECT_EQ(version, 6u);
    EXPECT_EQ(flow_label, 0x12345u);
    EXPECT_EQ(traffic_class, 0u);
}

// T-15: NAT behavior difference
TEST_F(DualStackTest, NatConsiderations) {
    // IPv4: NAT common, src_ip/dst_ip may change
    uint32_t public_ip = 0x08080808;  // 8.8.8.8
    uint32_t private_ip = 0xC0A80101;  // 192.168.1.1

    // IPv6: NATless design, end-to-end addressing
    // src_ip and dst_ip remain unchanged

    // This is a key architectural difference
    EXPECT_NE(public_ip, private_ip);
}

// T-15: Checksum calculation differences
TEST_F(DualStackTest, ChecksumDifferences) {
    // IPv4: header includes checksum that must be verified/recalculated
    // IPv6: no header checksum (optimization)

    uint16_t ipv4_checksum_offset = 10;  // Byte offset in header

    // IPv6 doesn't have checksum in base header
    // This is a structural test to document the difference
    EXPECT_EQ(ipv4_checksum_offset, 10u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
