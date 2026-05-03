/* SPDX-License-Identifier: MIT */
/*
 * test_bmh_performance.cpp - T-06: BMH Pattern Matching Performance Test
 *
 * Tests BMH algorithm performance with large payloads to establish benchmarks.
 * Validates that search time scales appropriately with payload size.
 */

#include "gtest/gtest.h"
#include "utils/bmh_search.h"
#include <chrono>
#include <vector>
#include <random>
#include <cstring>

using namespace nids;

class BMHPerformanceTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Generate random payload of given size
    static std::vector<uint8_t> generate_random_payload(size_t size, uint32_t seed = 42) {
        std::mt19937 gen(seed);
        std::uniform_int_distribution<> dis(0, 255);
        std::vector<uint8_t> payload(size);
        for (size_t i = 0; i < size; i++) {
            payload[i] = static_cast<uint8_t>(dis(gen));
        }
        return payload;
    }

    // Generate payload with known pattern embedded
    static std::vector<uint8_t> generate_payload_with_pattern(
        size_t total_size, const std::string& pattern, size_t offset) {
        std::vector<uint8_t> payload(total_size, 'X');
        if (offset + pattern.size() <= total_size) {
            std::memcpy(payload.data() + offset, pattern.data(), pattern.size());
        }
        return payload;
    }
};

// T-06: Benchmark - Small payload (1KB)
TEST_F(BMHPerformanceTest, Benchmark1KBPayload) {
    constexpr size_t PAYLOAD_SIZE = 1024;
    constexpr size_t NUM_ITERATIONS = 10000;

    std::string pattern = "test_pattern";
    auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 500);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double avg_ns = static_cast<double>(duration.count() * 1000) / NUM_ITERATIONS;

    // Should complete 10K iterations in well under 1 second
    EXPECT_LT(duration.count(), 1000000);  // Less than 1 second total
    EXPECT_LT(avg_ns, 1000.0);  // Less than 1us average per search

    printf("1KB payload: %.2f ns/search, %zu iterations in %ld ms\n",
           avg_ns, NUM_ITERATIONS, duration.count());
}

// T-06: Benchmark - Medium payload (10KB)
TEST_F(BMHPerformanceTest, Benchmark10KBPayload) {
    constexpr size_t PAYLOAD_SIZE = 10 * 1024;
    constexpr size_t NUM_ITERATIONS = 5000;

    std::string pattern = "test_pattern";
    auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 5000);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double avg_ns = static_cast<double>(duration.count() * 1000) / NUM_ITERATIONS;

    // Should complete 5K iterations reasonably fast
    EXPECT_LT(duration.count(), 2000000);  // Less than 2 seconds
    EXPECT_LT(avg_ns, 5000.0);  // Less than 5us average

    printf("10KB payload: %.2f ns/search, %zu iterations in %ld ms\n",
           avg_ns, NUM_ITERATIONS, duration.count());
}

// T-06: Benchmark - Large payload (100KB)
TEST_F(BMHPerformanceTest, Benchmark100KBPayload) {
    constexpr size_t PAYLOAD_SIZE = 100 * 1024;
    constexpr size_t NUM_ITERATIONS = 1000;

    std::string pattern = "test_pattern_longer_than_short";
    auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 50000);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double avg_ns = static_cast<double>(duration.count() * 1000) / NUM_ITERATIONS;

    // Should complete 1K iterations reasonably fast
    EXPECT_LT(duration.count(), 3000000);  // Less than 3 seconds
    EXPECT_LT(avg_ns, 50000.0);  // Less than 50us average

    printf("100KB payload: %.2f ns/search, %zu iterations in %ld ms\n",
           avg_ns, NUM_ITERATIONS, duration.count());
}

// T-06: Benchmark - Extra large payload (1MB)
TEST_F(BMHPerformanceTest, Benchmark1MBPayload) {
    constexpr size_t PAYLOAD_SIZE = 1024 * 1024;
    constexpr size_t NUM_ITERATIONS = 100;

    std::string pattern = "test_pattern_in_large_payload";
    auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 500000);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double avg_ns = static_cast<double>(duration.count() * 1000) / NUM_ITERATIONS;

    // Should complete 100 iterations within reasonable time
    EXPECT_LT(duration.count(), 5000000);  // Less than 5 seconds
    EXPECT_LT(avg_ns, 500000.0);  // Less than 500us average (1MB payload)

    printf("1MB payload: %.2f ns/search, %zu iterations in %ld ms\n",
           avg_ns, NUM_ITERATIONS, duration.count());
}

// T-06: Performance regression - Pattern at start vs end should be similar
TEST_F(BMHPerformanceTest, PatternPositionPerformance) {
    constexpr size_t PAYLOAD_SIZE = 10 * 1024;
    constexpr size_t NUM_ITERATIONS = 5000;
    std::string pattern = "PAT";

    // Pattern at start
    auto payload_start = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 0);
    auto start_start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload_start.data(), payload_start.size(), pattern);
    }
    auto end_start = std::chrono::high_resolution_clock::now();
    auto duration_start = std::chrono::duration_cast<std::chrono::microseconds>(end_start - start_start);

    // Pattern at end
    auto payload_end = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, PAYLOAD_SIZE - pattern.size());
    auto start_end = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload_end.data(), payload_end.size(), pattern);
    }
    auto end_end = std::chrono::high_resolution_clock::now();
    auto duration_end = std::chrono::duration_cast<std::chrono::microseconds>(end_end - start_end);

    // BMH typically performs well when pattern is near the end
    // Allow 3x difference to account for early-exit optimization
    // If durations are 0 (too fast), skip ratio check
    if (duration_start.count() > 0 && duration_end.count() > 0) {
        double ratio = static_cast<double>(duration_end.count()) / duration_start.count();
        EXPECT_LT(ratio, 3.0);
        printf("Pattern at start: %ld ms, at end: %ld ms, ratio: %.2f\n",
               duration_start.count(), duration_end.count(), ratio);
    } else {
        // Too fast to measure meaningfully
        printf("Pattern at start: %ld ms, at end: %ld ms (too fast to measure ratio)\n",
               duration_start.count(), duration_end.count());
    }
}

// T-06: Performance - Multiple pattern occurrences (should find first quickly)
TEST_F(BMHPerformanceTest, MultiplePatternOccurrences) {
    constexpr size_t PAYLOAD_SIZE = 10 * 1024;
    constexpr size_t NUM_ITERATIONS = 1000;
    std::string pattern = "AAAA";  // Common substring

    // Payload with pattern at start
    auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 0);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Should be fast since pattern is at start
    EXPECT_LT(duration.count(), 500000);  // Less than 0.5 seconds

    printf("Multiple occurrences (at start): %ld ms for %zu iterations\n",
           duration.count(), NUM_ITERATIONS);
}

// T-06: No-match worst case performance
TEST_F(BMHPerformanceTest, NoMatchWorstCase) {
    constexpr size_t PAYLOAD_SIZE = 10 * 1024;
    constexpr size_t NUM_ITERATIONS = 1000;
    std::string pattern = "NOTFOUND";

    // Random payload with no match
    auto payload = generate_random_payload(PAYLOAD_SIZE, 12345);

    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < NUM_ITERATIONS; i++) {
        search_payload(payload.data(), payload.size(), pattern);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Worst case: must scan entire payload
    EXPECT_LT(duration.count(), 2000000);  // Less than 2 seconds

    printf("No-match worst case: %ld ms for %zu iterations\n",
           duration.count(), NUM_ITERATIONS);
}

// T-06: Scalability test - O(n) linear scaling with payload size
TEST_F(BMHPerformanceTest, LinearScalability) {
    constexpr size_t NUM_ITERATIONS = 1000;
    std::string pattern = "TEST";

    std::vector<size_t> sizes = {1024, 2048, 4096, 8192};
    std::vector<double> times;

    for (size_t size : sizes) {
        auto payload = generate_payload_with_pattern(size, pattern, size / 2);

        auto start = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < NUM_ITERATIONS; i++) {
            search_payload(payload.data(), payload.size(), pattern);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
        times.push_back(static_cast<double>(duration.count()) / NUM_ITERATIONS);
    }

    // Check that time roughly doubles when size doubles (linear scaling)
    // Allow 3x tolerance for system variance
    // If times are too small (0), skip ratio check
    if (times[0] > 0 && times[1] > 0 && times[2] > 0 && times[3] > 0) {
        double ratio_2k_1k = times[1] / times[0];
        double ratio_4k_2k = times[2] / times[1];
        double ratio_8k_4k = times[3] / times[2];

        EXPECT_LT(ratio_2k_1k, 3.0);
        EXPECT_LT(ratio_4k_2k, 3.0);
        EXPECT_LT(ratio_8k_4k, 3.0);

        printf("Scalability: 1K=%.2f ns, 2K=%.2f ns (%.2fx), 4K=%.2f ns (%.2fx), 8K=%.2f ns (%.2fx)\n",
               times[0], times[1], ratio_2k_1k, times[2], ratio_4k_2k, times[3], ratio_8k_4k);
    } else {
        printf("Scalability: 1K=%.2f ns, 2K=%.2f ns, 4K=%.2f ns, 8K=%.2f ns (too fast to measure ratios)\n",
               times[0], times[1], times[2], times[3]);
    }
}

// T-06: Performance with various pattern lengths
TEST_F(BMHPerformanceTest, PatternLengthPerformance) {
    constexpr size_t PAYLOAD_SIZE = 10 * 1024;
    constexpr size_t NUM_ITERATIONS = 2000;

    std::vector<std::string> patterns = {
        "A",           // Single byte
        "AB",          // 2 bytes
        "ABC",         // 3 bytes
        "ABCD",        // 4 bytes
        "ABCDEFGH",    // 8 bytes
        "ABCDEFGHIJKL" // 12 bytes
    };

    for (const auto& pattern : patterns) {
        auto payload = generate_payload_with_pattern(PAYLOAD_SIZE, pattern, 5000);

        auto start = std::chrono::high_resolution_clock::now();
        for (size_t i = 0; i < NUM_ITERATIONS; i++) {
            search_payload(payload.data(), payload.size(), pattern);
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double avg_ns = static_cast<double>(duration.count() * 1000) / NUM_ITERATIONS;

        printf("Pattern len %zu: %.2f ns/search\n", pattern.size(), avg_ns);

        // All pattern lengths should complete in reasonable time
        EXPECT_LT(duration.count(), 1000000);  // Less than 1 second
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}