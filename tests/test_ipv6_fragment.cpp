/* SPDX-License-Identifier: MIT */
/*
 * test_ipv6_fragment.cpp - T-03: IPv6 fragment 重组测试
 *
 * 测试多个 fragment 的正确重组顺序
 */

#include "gtest/gtest.h"
#include <cstring>
#include <vector>
#include <algorithm>

// IPv6 Fragment Header (RFC 8200)
struct ipv6_frag_hdr {
    uint8_t    nexthdr;
    uint8_t    reserved;
    uint16_t   frag_off;       /* bits 0-12: offset, bits 13-14: reserved, bit 15: M flag */
    uint32_t   identification;
};

// Mock fragment for testing reassembly logic
struct mock_fragment {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint32_t identification;
    uint8_t  nexthdr;
    uint16_t offset;
    uint16_t size;
    bool     more_fragments;
    std::vector<uint8_t> data;
};

class IPv6FragmentTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to create fragment header
    static struct ipv6_frag_hdr make_frag_hdr(uint8_t nexthdr, uint16_t offset, bool more, uint32_t id) {
        struct ipv6_frag_hdr hdr;
        hdr.nexthdr = nexthdr;
        hdr.reserved = 0;
        hdr.frag_off = (offset / 8) | (more ? 0x0001 : 0);  // M flag in bit 15
        hdr.identification = id;
        return hdr;
    }

    // Helper to extract offset from fragment header
    // Note: frag_off is stored in host byte order in our mock struct
    static uint16_t get_offset(const struct ipv6_frag_hdr& hdr) {
        return (hdr.frag_off & 0xFFF8);  // bits 0-12
    }

    // Helper to check M flag
    static bool get_m_flag(const struct ipv6_frag_hdr& hdr) {
        return (hdr.frag_off & 0x0001) != 0;
    }
};

// T-03: Extract fragment offset correctly
TEST_F(IPv6FragmentTest, FragmentOffsetExtraction) {
    // Fragment offset = 1000 bytes
    struct ipv6_frag_hdr hdr = make_frag_hdr(6, 1000, true, 0x12345678);
    EXPECT_EQ(get_offset(hdr), 1000);

    // Fragment offset = 0 (first fragment)
    hdr = make_frag_hdr(6, 0, true, 0x12345678);
    EXPECT_EQ(get_offset(hdr), 0);

    // Fragment offset = 8000 bytes
    hdr = make_frag_hdr(6, 8000, false, 0x12345678);
    EXPECT_EQ(get_offset(hdr), 8000);
}

// T-03: Extract M flag correctly
TEST_F(IPv6FragmentTest, MFlagExtraction) {
    // More fragments = true
    struct ipv6_frag_hdr hdr1 = make_frag_hdr(6, 0, true, 0x12345678);
    EXPECT_TRUE(get_m_flag(hdr1));

    // More fragments = false (last fragment)
    struct ipv6_frag_hdr hdr2 = make_frag_hdr(6, 0, false, 0x12345678);
    EXPECT_FALSE(get_m_flag(hdr2));

    // M flag with non-zero offset
    struct ipv6_frag_hdr hdr3 = make_frag_hdr(6, 4000, true, 0x12345678);
    EXPECT_TRUE(get_m_flag(hdr3));
    EXPECT_EQ(get_offset(hdr3), 4000);
}

// T-03: Test fragment ordering - fragments arrive out of order
TEST_F(IPv6FragmentTest, ReassembleOutOfOrderFragments) {
    // Simulate fragments arriving out of order:
    // Fragment 1: offset=0, size=100, M=1
    // Fragment 3: offset=200, size=100, M=1
    // Fragment 2: offset=100, size=100, M=0 (last)

    std::vector<mock_fragment> fragments = {
        {0x20010001, 0x30010001, 0x12345678, 6, 0, 100, true, {}},   // frag 1
        {0x20010001, 0x30010001, 0x12345678, 6, 200, 100, true, {}},  // frag 3
        {0x20010001, 0x30010001, 0x12345678, 6, 100, 100, false, {}}  // frag 2
    };

    // Sort by offset
    std::sort(fragments.begin(), fragments.end(),
              [](const mock_fragment& a, const mock_fragment& b) {
                  return a.offset < b.offset;
              });

    // Verify order after sorting
    EXPECT_EQ(fragments[0].offset, 0);
    EXPECT_EQ(fragments[1].offset, 100);
    EXPECT_EQ(fragments[2].offset, 200);

    // Verify M flags
    EXPECT_TRUE(fragments[0].more_fragments);
    EXPECT_TRUE(fragments[1].more_fragments);
    EXPECT_FALSE(fragments[2].more_fragments);  // Last fragment
}

// T-03: Test fragment overlap detection (should not happen but defensive coding)
TEST_F(IPv6FragmentTest, DetectOverlappingFragments) {
    // Fragment 1: offset=0, size=100
    // Fragment 2: offset=50, size=100 (overlaps with frag 1)
    // Fragment 3: offset=150, size=100

    std::vector<mock_fragment> fragments = {
        {0x20010001, 0x30010001, 0x12345678, 6, 0, 100, true, {}},
        {0x20010001, 0x30010001, 0x12345678, 6, 50, 100, true, {}},  // Overlapping
        {0x20010001, 0x30010001, 0x12345678, 6, 150, 100, false, {}}
    };

    bool overlap_detected = false;
    for (size_t i = 1; i < fragments.size(); i++) {
        uint16_t prev_end = fragments[i-1].offset + fragments[i-1].size;
        if (fragments[i].offset < prev_end) {
            overlap_detected = true;
            break;
        }
    }

    EXPECT_TRUE(overlap_detected);
}

// T-03: Test complete reassembly calculation
TEST_F(IPv6FragmentTest, CalculateTotalReassembledLength) {
    // Simulate: frag1 (0-99), frag2 (100-199), frag3 (200-299)
    uint16_t total_length = 0;
    std::vector<mock_fragment> fragments = {
        {0x20010001, 0x30010001, 0x12345678, 6, 0, 100, true, {}},
        {0x20010001, 0x30010001, 0x12345678, 6, 100, 100, true, {}},
        {0x20010001, 0x30010001, 0x12345678, 6, 200, 100, false, {}}
    };

    // Sort by offset
    std::sort(fragments.begin(), fragments.end(),
              [](const mock_fragment& a, const mock_fragment& b) {
                  return a.offset < b.offset;
              });

    // Calculate total
    for (const auto& frag : fragments) {
        total_length += frag.size;
    }

    EXPECT_EQ(total_length, 300u);
}

// T-03: Test last fragment M=0 marks completion
TEST_F(IPv6FragmentTest, LastFragmentMFlagZero) {
    // Last fragment should have M=0
    struct ipv6_frag_hdr last_frag = make_frag_hdr(6, 8000, false, 0x12345678);
    EXPECT_FALSE(get_m_flag(last_frag));
}

// T-03: Test IPv6 fragment identification matching
TEST_F(IPv6FragmentTest, FragmentIdentificationMatching) {
    uint32_t id1 = 0x12345678;
    uint32_t id2 = 0x12345678;
    uint32_t id3 = 0x87654321;

    // Same identification should match
    EXPECT_EQ(id1, id2);

    // Different identification should not match
    EXPECT_NE(id1, id3);
}

// T-03: Test minimum fragment size (8-byte aligned)
TEST_F(IPv6FragmentTest, FragmentSizeAlignment) {
    // Fragment offset must be 8-byte aligned
    struct ipv6_frag_hdr hdr1 = make_frag_hdr(6, 0, true, 0x12345678);
    EXPECT_EQ(get_offset(hdr1) % 8, 0);

    struct ipv6_frag_hdr hdr2 = make_frag_hdr(6, 8, true, 0x12345678);
    EXPECT_EQ(get_offset(hdr2) % 8, 0);

    struct ipv6_frag_hdr hdr3 = make_frag_hdr(6, 16, false, 0x12345678);
    EXPECT_EQ(get_offset(hdr3) % 8, 0);
}

// T-03: Test multiple fragments with holes (missing middle fragments)
TEST_F(IPv6FragmentTest, DetectFragmentHoles) {
    // Fragment 1: offset=0, size=100
    // Fragment 3: offset=200, size=100
    // Missing: offset=100, size=100

    std::vector<mock_fragment> fragments = {
        {0x20010001, 0x30010001, 0x12345678, 6, 0, 100, true, {}},
        {0x20010001, 0x30010001, 0x12345678, 6, 200, 100, false, {}}
    };

    std::sort(fragments.begin(), fragments.end(),
              [](const mock_fragment& a, const mock_fragment& b) {
                  return a.offset < b.offset;
              });

    bool hole_detected = false;
    for (size_t i = 1; i < fragments.size(); i++) {
        uint16_t prev_end = fragments[i-1].offset + fragments[i-1].size;
        if (fragments[i].offset > prev_end) {
            hole_detected = true;
            break;
        }
    }

    EXPECT_TRUE(hole_detected);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}