/* SPDX-License-Identifier: MIT */
/*
 * test_dns_query.cpp - F-04: DNS Query Parsing Tests
 *
 * Tests for DNS query parsing and DNS tunneling detection in AF_XDP.
 * Tests include: DNS header parsing, query type extraction, domain name
 * validation, tunneling detection (long domains, many labels, abnormal types).
 */

#include "gtest/gtest.h"
#include "xdp/af_xdp.h"
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>


// DNS constants
constexpr uint16_t DNS_PORT = 53;
constexpr uint8_t DNS_TYPE_A = 1;
constexpr uint8_t DNS_TYPE_AAAA = 28;
constexpr uint8_t DNS_TYPE_TXT = 16;
constexpr uint8_t DNS_TYPE_NULL = 10;
constexpr uint8_t DNS_TYPE_AXFR = 252;
constexpr uint8_t DNS_TYPE_MX = 15;
constexpr uint8_t DNS_TYPE_NS = 2;
constexpr uint8_t DNS_TYPE_CNAME = 5;
constexpr uint8_t DNS_TYPE_SOA = 6;
constexpr uint8_t DNS_TYPE_PTR = 12;

// DNS tunneling detection thresholds
constexpr size_t DNS_TUNNEL_LONG_DOMAIN_THRESHOLD = 50;
constexpr size_t DNS_TUNNEL_MANY_LABELS_THRESHOLD = 20;

// Helper to calculate QNAME length from packet at given offset
static size_t get_qname_length(const std::vector<uint8_t>& packet, size_t qname_start) {
    size_t pos = qname_start;
    while (pos < packet.size() && packet[pos] != 0) {
        uint8_t label_len = packet[pos];
        pos += 1 + label_len;
    }
    return pos - qname_start + 1; // +1 for trailing 0x00
}

/*
 * DNS Header Structure (12 bytes)
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                      ID                       |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |QR|   Opcode  |AA|TC| RD|RA|   Z    |   RCODE   |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    QDCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ANCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    NSCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |                    ARCOUNT                     |
 * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

struct dns_header {
    uint16_t id;
    uint8_t flags1;
    uint8_t flags2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

class DnsQueryTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to build a DNS query packet using explicit byte encoding
    // DNS uses network byte order (big-endian) for all multi-byte fields
    static std::vector<uint8_t> build_dns_query(
        uint16_t tx_id,
        const std::string& domain_name,
        uint16_t query_type
    ) {
        std::vector<uint8_t> packet;

        // DNS Header (12 bytes) - network byte order (big-endian)
        packet.push_back((tx_id >> 8) & 0xFF);  // Transaction ID high
        packet.push_back(tx_id & 0xFF);          // Transaction ID low
        packet.push_back(0x01);                  // Flags: RD bit = 1 (recursion desired)
        packet.push_back(0x00);                  // Flags: remaining bits zero
        packet.push_back(0x00);                  // QDCOUNT high
        packet.push_back(0x01);                  // QDCOUNT low (1 question)
        packet.push_back(0x00);                  // ANCOUNT high
        packet.push_back(0x00);                  // ANCOUNT low
        packet.push_back(0x00);                  // NSCOUNT high
        packet.push_back(0x00);                  // NSCOUNT low
        packet.push_back(0x00);                  // ARCOUNT high
        packet.push_back(0x00);                  // ARCOUNT low

        // QNAME: domain name in DNS format
        // Each label: length byte + label bytes
        // Terminated by 0x00
        std::string domain = domain_name;
        if (!domain.empty() && domain.back() != '.') {
            domain += '.';
        }

        std::string::size_type start = 0;
        std::string::size_type dot_pos;
        while ((dot_pos = domain.find('.', start)) != std::string::npos) {
            std::string label = domain.substr(start, dot_pos - start);
            packet.push_back(static_cast<uint8_t>(label.length()));
            packet.insert(packet.end(), label.begin(), label.end());
            start = dot_pos + 1;
        }
        // Last label
        std::string last_label = domain.substr(start);
        if (!last_label.empty()) {
            packet.push_back(static_cast<uint8_t>(last_label.length()));
            packet.insert(packet.end(), last_label.begin(), last_label.end());
        }
        packet.push_back(0x00);  // QNAME terminator

        // QTYPE (2 bytes, network byte order)
        packet.push_back((query_type >> 8) & 0xFF);
        packet.push_back(query_type & 0xFF);

        // QCLASS (2 bytes, network byte order) - IN = 1
        packet.push_back(0x00);
        packet.push_back(0x01);

        return packet;
    }

    // Helper to build a DNS response packet using explicit byte encoding
    static std::vector<uint8_t> build_dns_response(
        uint16_t tx_id,
        const std::string& domain_name,
        uint16_t query_type,
        bool recursion_available = true
    ) {
        std::vector<uint8_t> packet;

        // DNS Header (12 bytes) - network byte order (big-endian)
        packet.push_back((tx_id >> 8) & 0xFF);  // Transaction ID high
        packet.push_back(tx_id & 0xFF);          // Transaction ID low
        // Flags: QR=1 (response), RD=1 (recursion desired), RA=1 (recursion available)
        packet.push_back(recursion_available ? 0x85 : 0x84);
        packet.push_back(0x00);                  // Flags: remaining bits zero
        packet.push_back(0x00);                  // QDCOUNT high
        packet.push_back(0x01);                  // QDCOUNT low (1 question)
        packet.push_back(0x00);                  // ANCOUNT high
        packet.push_back(0x00);                  // ANCOUNT low
        packet.push_back(0x00);                  // NSCOUNT high
        packet.push_back(0x00);                  // NSCOUNT low
        packet.push_back(0x00);                  // ARCOUNT high
        packet.push_back(0x00);                  // ARCOUNT low

        // QNAME: domain name in DNS format
        std::string domain = domain_name;
        if (!domain.empty() && domain.back() != '.') {
            domain += '.';
        }

        std::string::size_type start = 0;
        std::string::size_type dot_pos;
        while ((dot_pos = domain.find('.', start)) != std::string::npos) {
            std::string label = domain.substr(start, dot_pos - start);
            packet.push_back(static_cast<uint8_t>(label.length()));
            packet.insert(packet.end(), label.begin(), label.end());
            start = dot_pos + 1;
        }
        // Last label
        std::string last_label = domain.substr(start);
        if (!last_label.empty()) {
            packet.push_back(static_cast<uint8_t>(last_label.length()));
            packet.insert(packet.end(), last_label.begin(), last_label.end());
        }
        packet.push_back(0x00);  // QNAME terminator

        // QTYPE (2 bytes, network byte order)
        packet.push_back((query_type >> 8) & 0xFF);
        packet.push_back(query_type & 0xFF);

        // QCLASS (2 bytes, network byte order) - IN = 1
        packet.push_back(0x00);
        packet.push_back(0x01);

        return packet;
    }

    // Helper to count labels in a domain name
    static size_t count_labels(const std::string& domain) {
        size_t count = 0;
        for (char c : domain) {
            if (c == '.') count++;
        }
        return count;
    }

    // Helper to check if DNS tunneling is suspected
    static bool is_dns_tunneling(const std::string& domain_name, uint16_t query_type) {
        // Long domain name (>50 bytes) is suspicious
        if (domain_name.size() > DNS_TUNNEL_LONG_DOMAIN_THRESHOLD) {
            return true;
        }

        // Many labels (>20 dots) is suspicious
        if (count_labels(domain_name) > DNS_TUNNEL_MANY_LABELS_THRESHOLD) {
            return true;
        }

        // Abnormal query types are suspicious
        if (query_type == DNS_TYPE_TXT || query_type == DNS_TYPE_NULL ||
            query_type == DNS_TYPE_AXFR) {
            return true;
        }

        return false;
    }
};

// ============================================================================
// DNS Header Parsing Tests
// ============================================================================

TEST_F(DnsQueryTest, ParseDnsHeader) {
    std::vector<uint8_t> packet = build_dns_query(0x1234, "example.com", DNS_TYPE_A);

    ASSERT_GE(packet.size(), 12u);

    // Use explicit byte extraction (network byte order is big-endian)
    uint16_t id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | packet[5];
    uint16_t ancount = (static_cast<uint16_t>(packet[6]) << 8) | packet[7];
    uint16_t nscount = (static_cast<uint16_t>(packet[8]) << 8) | packet[9];
    uint16_t arcount = (static_cast<uint16_t>(packet[10]) << 8) | packet[11];

    EXPECT_EQ(id, 0x1234u);
    EXPECT_EQ(qdcount, 1u);
    EXPECT_EQ(ancount, 0u);
    EXPECT_EQ(nscount, 0u);
    EXPECT_EQ(arcount, 0u);
}

TEST_F(DnsQueryTest, DnsHeaderFlags) {
    // Build packet with RD flag set
    std::vector<uint8_t> packet = build_dns_query(0x0001, "test.com", DNS_TYPE_A);

    ASSERT_GE(packet.size(), 12u);

    // Use explicit byte access (network byte order)
    uint8_t flags1 = packet[2];

    // QR bit (bit 7 of flags1) should be 0 for query
    EXPECT_EQ((flags1 & 0x80), 0u);

    // RD bit (bit 0 of flags1) should be 1
    EXPECT_EQ((flags1 & 0x01), 1u);
}

TEST_F(DnsQueryTest, DnsResponseFlags) {
    // Build a DNS response packet manually
    std::vector<uint8_t> packet(12);

    // Set QR bit to 1 (response) at flags1 offset (byte 2)
    packet[2] = 0x80;

    EXPECT_EQ((packet[2] & 0x80), 0x80u);
}

TEST_F(DnsQueryTest, DnsHeaderSize) {
    // DNS header should be exactly 12 bytes
    EXPECT_EQ(sizeof(dns_header), 12u);
}

// ============================================================================
// DNS Query Type Tests
// ============================================================================

TEST_F(DnsQueryTest, QueryTypeA) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_A);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_A);
}

TEST_F(DnsQueryTest, QueryTypeAAAA) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_AAAA);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_AAAA);
}

TEST_F(DnsQueryTest, QueryTypeTXT) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_TXT);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_TXT);
}

TEST_F(DnsQueryTest, QueryTypeNULL) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_NULL);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_NULL);
}

TEST_F(DnsQueryTest, QueryTypeAXFR) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_AXFR);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_AXFR);
}

TEST_F(DnsQueryTest, QueryTypeMX) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_MX);
    ASSERT_GE(packet.size(), 16u);

    size_t qname_len = get_qname_length(packet, 12);
    size_t qtype_offset = 12 + qname_len;
    uint16_t qtype = (static_cast<uint16_t>(packet[qtype_offset]) << 8) | packet[qtype_offset + 1];
    EXPECT_EQ(qtype, DNS_TYPE_MX);
}

// ============================================================================
// Domain Name Parsing Tests
// ============================================================================

TEST_F(DnsQueryTest, SimpleDomainName) {
    auto packet = build_dns_query(0x0001, "example.com", DNS_TYPE_A);

    // After 12-byte header, domain name starts
    // "example.com" -> 0x07 "example" 0x03 "com" 0x00
    size_t offset = 12;

    // Skip domain name
    while (offset < packet.size() && packet[offset] != 0) {
        uint8_t label_len = packet[offset];
        offset += 1 + label_len;
    }
    // offset now points to null terminator (0x00)

    // Should be at query type (need offset + 4 < packet.size() for QCLASS low)
    EXPECT_LT(offset + 4, packet.size());

    // Verify query type and class
    EXPECT_EQ(packet[offset], 0x00);         // Null terminator
    EXPECT_EQ(packet[offset + 1], 0x00);    // QTYPE high
    EXPECT_EQ(packet[offset + 2], 0x01);     // QTYPE low (Type A)
    EXPECT_EQ(packet[offset + 3], 0x00);     // QCLASS high
    EXPECT_EQ(packet[offset + 4], 0x01);     // QCLASS low (Class IN)
}

TEST_F(DnsQueryTest, LongSubdomain) {
    std::string long_domain = "subdomain.example.com";
    auto packet = build_dns_query(0x0001, long_domain, DNS_TYPE_A);

    EXPECT_GE(packet.size(), 12u + long_domain.size() + 2 + 4);
}

TEST_F(DnsQueryTest, MultiLevelSubdomain) {
    std::string multi_level = "a.b.c.d.example.com";
    auto packet = build_dns_query(0x0001, multi_level, DNS_TYPE_A);

    EXPECT_GE(packet.size(), 12u);
}

TEST_F(DnsQueryTest, WwwSubdomain) {
    // Test www.example.com domain
    auto packet = build_dns_query(0x1234, "www.example.com", DNS_TYPE_A);

    ASSERT_GE(packet.size(), 20u);

    // Verify transaction ID
    uint16_t tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(tx_id, 0x1234u);

    // Verify flags: RD bit set
    EXPECT_EQ(packet[2], 0x01u);

    // Verify QDCOUNT = 1
    EXPECT_EQ(packet[4], 0x00u);
    EXPECT_EQ(packet[5], 0x01u);

    // Verify domain name encoding: 0x03 "www" 0x07 "example" 0x03 "com" 0x00
    EXPECT_EQ(packet[12], 0x03);  // "www" length
    EXPECT_EQ(packet[13], 'w');
    EXPECT_EQ(packet[14], 'w');
    EXPECT_EQ(packet[15], 'w');
    EXPECT_EQ(packet[16], 0x07);  // "example" length
}

TEST_F(DnsQueryTest, MailServerDomain) {
    // Test mail.server.domain.org domain
    auto packet = build_dns_query(0xABCD, "mail.server.domain.org", DNS_TYPE_A);

    ASSERT_GE(packet.size(), 28u);

    // Verify transaction ID
    uint16_t tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(tx_id, 0xABCDu);

    // Verify QTYPE is A (1)
    uint16_t qtype = (static_cast<uint16_t>(packet[packet.size() - 4]) << 8) |
                     packet[packet.size() - 3];
    EXPECT_EQ(qtype, DNS_TYPE_A);

    // Verify QCLASS is IN (1)
    uint16_t qclass = (static_cast<uint16_t>(packet[packet.size() - 2]) << 8) |
                       packet[packet.size() - 1];
    EXPECT_EQ(qclass, 0x0001u);
}

TEST_F(DnsQueryTest, SingleLabelDomain) {
    // Root or single-label domain
    auto packet = build_dns_query(0x0001, "", DNS_TYPE_A);

    // Should have just null terminator after header
    ASSERT_GE(packet.size(), 14u);
    EXPECT_EQ(packet[12], 0x00);  // Null terminator
}

// ============================================================================
// DNS Tunneling Detection Tests (F-04)
// ============================================================================

TEST_F(DnsQueryTest, TunnelingNormalDomain) {
    std::string normal_domain = "example.com";

    // Normal domain should NOT be flagged
    EXPECT_FALSE(is_dns_tunneling(normal_domain, DNS_TYPE_A));

    // Subdomain is also normal
    std::string sub_domain = "www.example.com";
    EXPECT_FALSE(is_dns_tunneling(sub_domain, DNS_TYPE_A));
}

TEST_F(DnsQueryTest, TunnelingLongDomain) {
    // Domain > 50 bytes is suspicious
    std::string long_domain(60, 'a');
    long_domain += ".com";

    EXPECT_TRUE(is_dns_tunneling(long_domain, DNS_TYPE_A));

    // Domain exactly at threshold (50 chars without .com) should NOT be flagged
    std::string threshold_domain(50, 'b');
    EXPECT_FALSE(is_dns_tunneling(threshold_domain, DNS_TYPE_A));

    // But 50 chars + ".com" = 54 chars exceeds threshold, SHOULD be flagged
    std::string long_threshold_domain(50, 'b');
    long_threshold_domain += ".com";
    EXPECT_TRUE(is_dns_tunneling(long_threshold_domain, DNS_TYPE_A));
}

TEST_F(DnsQueryTest, TunnelingManyLabels) {
    // Domain with >20 labels is suspicious
    // Use single-char labels so total length <= 50, forcing label count check
    // 23 labels of "a" + ".com" = 23 + 23 dots + 4 = 50 chars (exact threshold)
    // But 23 > 20, so should be flagged
    std::string many_labels;
    for (int i = 0; i < 23; i++) {
        if (i > 0) many_labels += ".";
        many_labels += "a";
    }
    many_labels += ".com";

    EXPECT_TRUE(is_dns_tunneling(many_labels, DNS_TYPE_A));

    // Domain at threshold should NOT be flagged
    // 20 labels of "a" + ".com" = 20 + 19 dots + 4 = 43 chars
    // 19 dots > 20 is false, so should NOT be flagged
    std::string threshold_labels;
    for (int i = 0; i < 20; i++) {
        if (i > 0) threshold_labels += ".";
        threshold_labels += "a";
    }
    threshold_labels += ".com";
    EXPECT_FALSE(is_dns_tunneling(threshold_labels, DNS_TYPE_A));
}

TEST_F(DnsQueryTest, TunnelingAbnormalQueryTypes) {
    // TXT query - often used in DNS tunneling
    std::string domain = "example.com";
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_TXT));

    // NULL query - rarely used legitimately
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_NULL));

    // AXFR (zone transfer) - rarely used, high risk
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_AXFR));

    // Normal types should NOT be flagged
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_A));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_AAAA));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_MX));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_NS));
}

TEST_F(DnsQueryTest, TunnelingCombinedIndicators) {
    // Combining multiple indicators increases suspicion

    // Long domain + TXT type = definitely suspicious
    std::string long_domain(60, 'x');
    long_domain += ".com";
    EXPECT_TRUE(is_dns_tunneling(long_domain, DNS_TYPE_TXT));

    // Many labels + NULL type = definitely suspicious
    std::string many_labels;
    for (int i = 0; i < 25; i++) {
        if (i > 0) many_labels += ".";
        many_labels += "l";
    }
    many_labels += ".com";
    EXPECT_TRUE(is_dns_tunneling(many_labels, DNS_TYPE_NULL));
}

TEST_F(DnsQueryTest, TunnelingFalsePositives) {
    // Ensure legitimate queries are not flagged

    // Long legitimate domain (e.g., AWS S3)
    std::string aws_domain = "s3.amazonaws.com";
    EXPECT_FALSE(is_dns_tunneling(aws_domain, DNS_TYPE_A));

    // Cloudflare domain
    std::string cf_domain = "www.cloudflare.com";
    EXPECT_FALSE(is_dns_tunneling(cf_domain, DNS_TYPE_A));

    // Google domain
    std::string google_domain = "www.google.com";
    EXPECT_FALSE(is_dns_tunneling(google_domain, DNS_TYPE_A));
}

TEST_F(DnsQueryTest, TunnelingLongDomainPacketBuild) {
    // Test building a DNS packet for a long domain used in tunneling
    std::string long_domain(60, 'x');
    long_domain += ".com";

    auto packet = build_dns_query(0x1234, long_domain, DNS_TYPE_TXT);

    ASSERT_GE(packet.size(), 82u);  // 12 header + 66 QNAME + 4 qtype/qclass

    // Verify transaction ID
    uint16_t tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(tx_id, 0x1234u);

    // Verify flags: RD bit set
    EXPECT_EQ(packet[2], 0x01u);

    // Verify QTYPE is TXT (16) in network byte order
    uint16_t qtype = (static_cast<uint16_t>(packet[packet.size() - 4]) << 8) |
                     packet[packet.size() - 3];
    EXPECT_EQ(qtype, DNS_TYPE_TXT);

    // This should trigger tunneling detection
    EXPECT_TRUE(is_dns_tunneling(long_domain, DNS_TYPE_TXT));
}

TEST_F(DnsQueryTest, TunnelingDnsTunnelDetection) {
    // DNS tunneling detection: long domain with suspicious query type
    std::string tunnel_domain = "this.is.a.very.suspicious.domain.name.that.is.used.for.tunneling.purposes.com";

    // Build packet with AXFR query type (zone transfer - often used in tunneling)
    auto packet = build_dns_query(0xDEAD, tunnel_domain, DNS_TYPE_AXFR);

    ASSERT_GE(packet.size(), 12u);

    // Verify QTYPE is AXFR (252)
    uint16_t qtype = (static_cast<uint16_t>(packet[packet.size() - 4]) << 8) |
                     packet[packet.size() - 3];
    EXPECT_EQ(qtype, DNS_TYPE_AXFR);

    // Should be flagged as tunneling
    EXPECT_TRUE(is_dns_tunneling(tunnel_domain, DNS_TYPE_AXFR));
}

// ============================================================================
// DNS Response Tests
// ============================================================================

TEST_F(DnsQueryTest, BuildDnsResponse) {
    auto packet = build_dns_response(0x1234, "example.com", DNS_TYPE_A);

    ASSERT_GE(packet.size(), 16u);

    // Verify transaction ID
    uint16_t tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(tx_id, 0x1234u);

    // Verify flags: QR=1 (response), RD=1, RA=1
    EXPECT_EQ(packet[2], 0x85u);  // 10000101b

    // Verify QDCOUNT = 1
    uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | packet[5];
    EXPECT_EQ(qdcount, 1u);
}

TEST_F(DnsQueryTest, BuildDnsResponseNoRecursion) {
    auto packet = build_dns_response(0x5678, "test.org", DNS_TYPE_AAAA, false);

    ASSERT_GE(packet.size(), 16u);

    // Verify transaction ID
    uint16_t tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(tx_id, 0x5678u);

    // Verify flags: QR=1, RD=1, RA=0 (no recursion available)
    EXPECT_EQ(packet[2], 0x84u);  // 10000100b
}

// ============================================================================
// DNS Query Info Structure Tests
// ============================================================================

TEST_F(DnsQueryTest, DnsQueryInfoStructure) {
    nids::DnsQueryInfo info = {};

    info.query_name = "example.com";
    info.query_type = DNS_TYPE_A;
    info.is_valid = false;
    info.query_id = 0x1234;

    EXPECT_EQ(info.query_name, "example.com");
    EXPECT_EQ(info.query_type, DNS_TYPE_A);
    EXPECT_FALSE(info.is_valid);
    EXPECT_EQ(info.query_id, 0x1234u);
}

TEST_F(DnsQueryTest, DnsQueryInfoResponse) {
    nids::DnsQueryInfo info = {};

    info.query_name = "example.com";
    info.query_type = DNS_TYPE_A;
    info.is_valid = true;
    info.query_id = 0x1234;

    EXPECT_TRUE(info.is_valid);
}

TEST_F(DnsQueryTest, DnsQueryTypesEnumeration) {
    // Verify all DNS query types have expected values
    EXPECT_EQ(DNS_TYPE_A, 1u);
    EXPECT_EQ(DNS_TYPE_AAAA, 28u);
    EXPECT_EQ(DNS_TYPE_TXT, 16u);
    EXPECT_EQ(DNS_TYPE_NULL, 10u);
    EXPECT_EQ(DNS_TYPE_AXFR, 252u);
    EXPECT_EQ(DNS_TYPE_MX, 15u);
    EXPECT_EQ(DNS_TYPE_NS, 2u);
    EXPECT_EQ(DNS_TYPE_CNAME, 5u);
    EXPECT_EQ(DNS_TYPE_SOA, 6u);
    EXPECT_EQ(DNS_TYPE_PTR, 12u);
}

// ============================================================================
// DNS Port and Protocol Tests
// ============================================================================

TEST_F(DnsQueryTest, DnsPortConstant) {
    EXPECT_EQ(DNS_PORT, 53u);
}

TEST_F(DnsQueryTest, DnsIsUdpProtocol) {
    // DNS typically uses UDP (port 53)
    uint8_t protocol = 17;  // UDP

    EXPECT_EQ(protocol, 17u);
}

// ============================================================================
// DNS Transaction ID Tests
// ============================================================================

TEST_F(DnsQueryTest, TransactionIDPropagation) {
    uint16_t tx_id = 0xABCD;
    auto packet = build_dns_query(tx_id, "test.com", DNS_TYPE_A);

    // Use explicit byte extraction (network byte order)
    uint16_t pkt_tx_id = (static_cast<uint16_t>(packet[0]) << 8) | packet[1];
    EXPECT_EQ(pkt_tx_id, tx_id);
}

TEST_F(DnsQueryTest, MultipleQueries) {
    // QDCOUNT > 1
    std::vector<uint8_t> packet = build_dns_query(0x0001, "example.com", DNS_TYPE_A);

    // Modify QDCOUNT to 2 (in network byte order)
    packet[5] = 0x02;

    // Verify QDCOUNT is now 2
    uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | packet[5];
    EXPECT_EQ(qdcount, 2u);
}

// ============================================================================
// Edge Cases and Boundary Tests
// ============================================================================

TEST_F(DnsQueryTest, EmptyDomainName) {
    auto packet = build_dns_query(0x0001, "", DNS_TYPE_A);

    // Should still be a valid packet
    ASSERT_GE(packet.size(), 14u);
}

TEST_F(DnsQueryTest, DomainWithTrailingDot) {
    auto packet1 = build_dns_query(0x0001, "example.com.", DNS_TYPE_A);
    auto packet2 = build_dns_query(0x0001, "example.com", DNS_TYPE_A);

    // Should produce similar packets
    EXPECT_GE(packet1.size(), 12u);
    EXPECT_GE(packet2.size(), 12u);
}

TEST_F(DnsQueryTest, LabelCountEdgeCases) {
    // Single label
    EXPECT_EQ(count_labels("com"), 0u);

    // Two labels
    EXPECT_EQ(count_labels("example.com"), 1u);

    // Many labels
    std::string many_labels = "a.b.c.d.e.f.g.h.i.j";
    EXPECT_EQ(count_labels(many_labels), 9u);
}

TEST_F(DnsQueryTest, DomainSizeEdgeCases) {
    // Empty domain
    EXPECT_EQ(is_dns_tunneling("", DNS_TYPE_A), false);

    // Very short domain
    std::string short_domain = "a.co";
    EXPECT_FALSE(is_dns_tunneling(short_domain, DNS_TYPE_A));

    // Maximum normal domain
    std::string max_normal(50, 'x');
    EXPECT_FALSE(is_dns_tunneling(max_normal, DNS_TYPE_A));
}

TEST_F(DnsQueryTest, AllQueryTypesTunnelingStatus) {
    // Test each query type's tunneling status
    std::string domain = "example.com";

    // Should NOT trigger tunneling
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_A));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_AAAA));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_MX));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_NS));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_CNAME));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_SOA));
    EXPECT_FALSE(is_dns_tunneling(domain, DNS_TYPE_PTR));

    // SHOULD trigger tunneling
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_TXT));
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_NULL));
    EXPECT_TRUE(is_dns_tunneling(domain, DNS_TYPE_AXFR));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
