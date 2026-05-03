/* SPDX-License-Identifier: MIT */
/*
 * test_rule_parsing_boundaries.cpp - T-02: 规则解析边界测试
 *
 * 测试 port range 65535:1 (无效范围) 的解析
 */

#include "gtest/gtest.h"
#include "rules/rule_parser.h"

using namespace nids;

class RuleParsingBoundaryTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// T-02: Invalid port range where end < start (65535:1)
TEST_F(RuleParsingBoundaryTest, InvalidPortRangeEndLessThanStart) {
    RuleParser parser;
    MatchRule rule;

    // Port range 65535:1 is invalid - end (1) < start (65535)
    EXPECT_FALSE(parser.parse_line(R"(1 6 65535:1 "" "Invalid range")", rule));
    EXPECT_FALSE(parser.error().empty());
    EXPECT_NE(parser.error().find("max < min"), std::string::npos);
}

// T-02: Invalid port range where both are equal (should this be valid?)
TEST_F(RuleParsingBoundaryTest, PortRangeEqualPorts) {
    RuleParser parser;
    MatchRule rule;

    // Port range 80:80 is technically valid (single port 80)
    EXPECT_TRUE(parser.parse_line(R"(1 6 80:80 "" "Single port via range")", rule));
    EXPECT_EQ(rule.dst_port, 80);
    EXPECT_EQ(rule.dst_port_max, 80);
}

// T-02: Valid port ranges at boundaries
TEST_F(RuleParsingBoundaryTest, ValidPortRangeBoundaries) {
    RuleParser parser;
    MatchRule rule;

    // 1:65535 is valid (all ports)
    EXPECT_TRUE(parser.parse_line(R"(1 6 1:65535 "" "All TCP ports")", rule));
    EXPECT_EQ(rule.dst_port, 1);
    EXPECT_EQ(rule.dst_port_max, 65535);

    // 1:1 is valid (single port 1)
    EXPECT_TRUE(parser.parse_line(R"(2 6 1:1 "" "Port 1")", rule));
    EXPECT_EQ(rule.dst_port, 1);
    EXPECT_EQ(rule.dst_port_max, 1);
}

// T-02: Invalid port 0
TEST_F(RuleParsingBoundaryTest, InvalidPortZero) {
    RuleParser parser;
    MatchRule rule;

    // Port 0 is invalid (must be 1-65535)
    EXPECT_FALSE(parser.parse_line(R"(1 6 0 "" "Port zero")", rule));
}

// T-02: Invalid port 65536
TEST_F(RuleParsingBoundaryTest, InvalidPort65536) {
    RuleParser parser;
    MatchRule rule;

    // Port 65536 is invalid (max is 65535)
    EXPECT_FALSE(parser.parse_line(R"(1 6 65536 "" "Port too high")", rule));
}

// T-02: Invalid port range start > 65535
TEST_F(RuleParsingBoundaryTest, InvalidPortRangeStartTooHigh) {
    RuleParser parser;
    MatchRule rule;

    // Port start 65536:80 is invalid
    EXPECT_FALSE(parser.parse_line(R"(1 6 65536:80 "" "Start port too high")", rule));
}

// T-02: Invalid port range end > 65535
TEST_F(RuleParsingBoundaryTest, InvalidPortRangeEndTooHigh) {
    RuleParser parser;
    MatchRule rule;

    // Port range 80:65536 is invalid
    EXPECT_FALSE(parser.parse_line(R"(1 6 80:65536 "" "End port too high")", rule));
}

// T-02: Valid single port boundaries
TEST_F(RuleParsingBoundaryTest, ValidSinglePortBoundaries) {
    RuleParser parser;
    MatchRule rule;

    // Port 1 is minimum valid
    EXPECT_TRUE(parser.parse_line(R"(1 6 1 "" "Min port")", rule));
    EXPECT_EQ(rule.dst_port, 1);

    // Port 65535 is maximum valid
    EXPECT_TRUE(parser.parse_line(R"(2 6 65535 "" "Max port")", rule));
    EXPECT_EQ(rule.dst_port, 65535);
}

// T-02: Port range with port 0 in start position
TEST_F(RuleParsingBoundaryTest, InvalidPortRangeStartZero) {
    RuleParser parser;
    MatchRule rule;

    // Port range 0:100 is invalid (start cannot be 0)
    EXPECT_FALSE(parser.parse_line(R"(1 6 0:100 "" "Start port zero")", rule));
}

// T-02: Port range with port 0 in end position
TEST_F(RuleParsingBoundaryTest, InvalidPortRangeEndZero) {
    RuleParser parser;
    MatchRule rule;

    // Port range 100:0 is invalid (end cannot be 0)
    EXPECT_FALSE(parser.parse_line(R"(1 6 100:0 "" "End port zero")", rule));
}

// T-02: Empty content rule with valid port range
TEST_F(RuleParsingBoundaryTest, ValidPortRangeEmptyContent) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(1 6 8000:9000 "" "HTTP range")", rule));
    EXPECT_EQ(rule.dst_port, 8000);
    EXPECT_EQ(rule.dst_port_max, 9000);
    EXPECT_TRUE(rule.content.empty());
    EXPECT_FALSE(rule.need_dpi);
}

// T-02: Port range with content rule
TEST_F(RuleParsingBoundaryTest, ValidPortRangeWithContent) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(1 6 80:90 "evil" "Suspicious")", rule));
    EXPECT_EQ(rule.dst_port, 80);
    EXPECT_EQ(rule.dst_port_max, 90);
    EXPECT_EQ(rule.content, "evil");
    EXPECT_TRUE(rule.need_dpi);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}