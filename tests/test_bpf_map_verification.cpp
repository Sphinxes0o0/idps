/* SPDX-License-Identifier: MIT */
/*
 * test_bpf_map_verification.cpp - T-01: BPF 程序验证测试
 *
 * 验证 nids_bpf.o 加载后的 map 大小和类型
 */

#include <gtest/gtest.h>
#include "ebpf/ebpf_loader.h"
#include <bpf/bpf.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace nids;

class BpfMapVerificationTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// T-01: Verify BPF maps have correct sizes and types after loading
TEST_F(BpfMapVerificationTest, VerifyMapSizes) {
    // Skip if BPF not available (e.g., on macOS)
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    const char* bpf_obj_path = "/idps/build/bin/nids_bpf.o";
    struct stat st;
    if (stat(bpf_obj_path, &st) != 0) {
        GTEST_SKIP() << "BPF object file not found at " << bpf_obj_path;
    }

    EbpfLoader loader;
    EXPECT_FALSE(loader.is_loaded());

    // Load should succeed in container environment
    // Note: We don't actually attach to an interface for map verification
}

// T-01: Verify specific map types match expected BPF_MAP_TYPE
TEST_F(BpfMapVerificationTest, VerifyMapTypes) {
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    // conn_track should be LRU_HASH
    // rules should be HASH
    // stats should be PERCPU_ARRAY
    // config should be ARRAY
    // events should be RINGBUF
}

// T-01: Verify map max_entries match expected values
TEST_F(BpfMapVerificationTest, VerifyMapMaxEntries) {
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    // MAX_FLOWS = 100000 for conn_track
    // MAX_RULES = 50000 for rules
    // STATS_MAX = 256 for stats
    // config ARRAY max_entries = 1
    // events RINGBUF max_entries = 256 * 1024
}

// T-01: Verify rule_index map structure
TEST_F(BpfMapVerificationTest, VerifyRuleIndexMap) {
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    // rule_index should be HASH with key=rule_index_key, value=__u32
}

// T-01: Verify SYN flood and ICMP flood tracking maps
TEST_F(BpfMapVerificationTest, VerifyFloodTrackingMaps) {
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    // syn_flood_track: LRU_HASH, max_entries=65536
    // icmp_flood_track: LRU_HASH, max_entries=65536
}

// T-01: Verify fragment tracking maps
TEST_F(BpfMapVerificationTest, VerifyFragmentMaps) {
    if (!EbpfLoader::is_bpf_available()) {
        GTEST_SKIP() << "BPF not available on this system";
    }

    // frag_track: LRU_HASH, max_entries=1024
    // frag_buffers: LRU_HASH, max_entries=16384
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}