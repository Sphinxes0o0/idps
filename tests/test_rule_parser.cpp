/* SPDX-License-Identifier: MIT */
/*
 * test_rule_parser.cpp - RuleParser 单元测试
 */

#include "gtest/gtest.h"
#include "rules/rule_parser.h"
#include <fstream>
#include <filesystem>

using namespace nids;

class RuleParserTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(RuleParserTest, ParseValidLine) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(1 6 80 "GET /evil" "Suspicious HTTP")", rule));
    EXPECT_EQ(rule.id, 1);
    EXPECT_EQ(rule.proto, 6);
    EXPECT_EQ(rule.dst_port, 80);
    EXPECT_EQ(rule.content, "GET /evil");
    EXPECT_EQ(rule.message, "Suspicious HTTP");
    EXPECT_TRUE(rule.need_dpi);
}

TEST_F(RuleParserTest, ParseEmptyContent) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(8 6 22 "" "SSH connection")", rule));
    EXPECT_EQ(rule.id, 8);
    EXPECT_EQ(rule.proto, 6);
    EXPECT_EQ(rule.dst_port, 22);
    EXPECT_TRUE(rule.content.empty());
    EXPECT_FALSE(rule.need_dpi);
}

TEST_F(RuleParserTest, ParseAnyProtocol) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(10 0 0 "" "Any traffic")", rule));
    EXPECT_EQ(rule.id, 10);
    EXPECT_EQ(rule.proto, 0);
    EXPECT_EQ(rule.dst_port, 0);
    EXPECT_FALSE(rule.need_dpi);
}

TEST_F(RuleParserTest, ParseUDP) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_TRUE(parser.parse_line(R"(7 17 53 "" "DNS query")", rule));
    EXPECT_EQ(rule.proto, 17);
    EXPECT_EQ(rule.dst_port, 53);
}

TEST_F(RuleParserTest, SkipComment) {
    RuleParser parser;
    MatchRule rule;

    EXPECT_FALSE(parser.parse_line("# This is a comment", rule));
    EXPECT_FALSE(parser.parse_line("", rule));
    EXPECT_FALSE(parser.parse_line("   ", rule));
}

TEST_F(RuleParserTest, ParseFile) {
    // Create temp rules file
    std::string temp_path = "/tmp/test_rules.txt";
    {
        std::ofstream f(temp_path);
        f << "# Test rules\n";
        f << R"(1 6 80 "GET /test" "Test rule")" << "\n";
        f << R"(2 6 22 "" "SSH")" << "\n";
        f << R"(3 17 53 "" "DNS")" << "\n";
    }

    RuleParser parser;
    RuleSet rs = parser.parse_file(temp_path);

    EXPECT_EQ(rs.simple_rules.size(), 2u);  // rules 2 and 3 (empty content)
    EXPECT_EQ(rs.content_rules.size(), 1u);  // rule 1 (has content)

    // Cleanup
    std::filesystem::remove(temp_path);
}

TEST_F(RuleParserTest, FileNotFound) {
    RuleParser parser;
    RuleSet rs = parser.parse_file("/nonexistent/path/rules.txt");
    EXPECT_TRUE(rs.simple_rules.empty());
    EXPECT_TRUE(rs.content_rules.empty());
    EXPECT_FALSE(parser.error().empty());
}
