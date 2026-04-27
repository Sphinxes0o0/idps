/* SPDX-License-Identifier: MIT */
/*
 * test_bmh_search.cpp - Boyer-Moore-Horspool 单元测试
 */

#include "gtest/gtest.h"
#include "utils/bmh_search.h"

using namespace nids;

class BMHSearchTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test 1: Basic match - pattern found in middle of payload
TEST_F(BMHSearchTest, BasicMatchInMiddle) {
    const uint8_t payload[] = "Hello World, this is a test";
    std::string pattern = "World";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 2: Match at start - pattern at beginning of payload
TEST_F(BMHSearchTest, MatchAtStart) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "Hello";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 3: Match at end - pattern at end of payload
TEST_F(BMHSearchTest, MatchAtEnd) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "World";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 4: No match - pattern not in payload
TEST_F(BMHSearchTest, NoMatch) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "Python";

    EXPECT_FALSE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 5: Empty payload - data is null or len is 0
TEST_F(BMHSearchTest, EmptyPayload) {
    const uint8_t* payload = nullptr;
    std::string pattern = "test";

    EXPECT_FALSE(search_payload(payload, 0, pattern));
}

TEST_F(BMHSearchTest, ZeroLengthPayload) {
    const uint8_t payload[] = "";
    std::string pattern = "test";

    EXPECT_FALSE(search_payload(payload, 0, pattern));
}

// Test 6: Empty pattern - pattern is empty string (edge case)
TEST_F(BMHSearchTest, EmptyPattern) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "";

    // Empty pattern matches everything (per implementation)
    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 7: Pattern longer than payload - should return false
TEST_F(BMHSearchTest, PatternLongerThanPayload) {
    const uint8_t payload[] = "Hi";
    std::string pattern = "Hello World";

    EXPECT_FALSE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 8: Pattern equal to payload - exact match
TEST_F(BMHSearchTest, PatternEqualToPayload) {
    const uint8_t payload[] = "Hello";
    std::string pattern = "Hello";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 9: Multiple occurrences - only need to find one (BMH returns on first match)
TEST_F(BMHSearchTest, MultipleOccurrences) {
    const uint8_t payload[] = "AAAAAAAAB";
    std::string pattern = "AAA";

    // Should find at least one occurrence
    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 10: Single byte pattern - finding a single character
TEST_F(BMHSearchTest, SingleBytePattern) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "o";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, SingleBytePatternNotFound) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "z";

    EXPECT_FALSE(search_payload(payload, sizeof(payload) - 1, pattern));
}

// Test 11: Binary data - payload with null bytes in the middle
TEST_F(BMHSearchTest, BinaryDataWithNullBytes) {
    const uint8_t payload[] = {'H', 'e', 'l', 'l', 'o', '\0', 'W', 'o', 'r', 'l', 'd'};
    std::string pattern = "World";

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

TEST_F(BMHSearchTest, BinaryDataSearchNullByte) {
    const uint8_t payload[] = {'H', 'e', 'l', 'l', 'o', '\0', 'W', 'o', 'r', 'l', 'd'};
    std::string pattern = "lo\0Wo";  // pattern with embedded null

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

TEST_F(BMHSearchTest, BinaryDataOnlyNullBytes) {
    const uint8_t payload[] = {'\0', '\0', '\0', '\0'};
    std::string pattern = "\0\0";  // pattern of null bytes

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

// Test 12: Pattern with special characters - bytes 0x00, 0xFF, etc.
TEST_F(BMHSearchTest, SpecialByteFF) {
    const uint8_t payload[] = {'H', 'e', 'l', 'l', 'o', '\xFF', 'W', 'o', 'r', 'l', 'd'};
    std::string pattern = "World";

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

TEST_F(BMHSearchTest, SpecialByteFFAtStart) {
    const uint8_t payload[] = {'\xFF', 'H', 'e', 'l', 'l', 'o'};
    std::string pattern = "\xFFHe";

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

TEST_F(BMHSearchTest, PatternWith0x00) {
    const uint8_t payload[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f'};
    std::string pattern = "c\0d";  // pattern containing null byte

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

TEST_F(BMHSearchTest, PatternWith0xFF) {
    const uint8_t payload[] = {'a', 'b', 'c', '\xFF', 'd', 'e', 'f'};
    // Construct pattern byte-by-byte to avoid hex escape parsing issues
    std::string pattern;
    pattern.push_back('c');
    pattern.push_back('\xFF');
    pattern.push_back('d');

    EXPECT_TRUE(search_payload(payload, sizeof(payload), pattern));
}

// Additional edge case tests
TEST_F(BMHSearchTest, CaseSensitive) {
    const uint8_t payload[] = "Hello World";
    std::string pattern = "hello";

    EXPECT_FALSE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, PatternAtPayloadBoundary) {
    const uint8_t payload[] = "AB";
    std::string pattern = "B";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, LongPattern) {
    const uint8_t payload[] = "This is a very long payload that contains a secret pattern somewhere in the middle of the text";
    std::string pattern = "secret pattern";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, PayloadWithOnlyPattern) {
    const uint8_t payload[] = "test";
    std::string pattern = "test";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, PayloadSlightlyLongerThanPattern) {
    const uint8_t payload[] = "testX";
    std::string pattern = "test";

    EXPECT_TRUE(search_payload(payload, sizeof(payload) - 1, pattern));
}

TEST_F(BMHSearchTest, PayloadOneByteShorterThanPattern) {
    const uint8_t payload[] = "tes";
    std::string pattern = "test";

    EXPECT_FALSE(search_payload(payload, sizeof(payload) - 1, pattern));
}
