/* SPDX-License-Identifier: MIT */
/*
 * test_rule_index_consistency.cpp - T-14: Rule Index Consistency Test
 *
 * Tests that verify rule_index map is consistent with rules map.
 * rule_index provides O(1) lookup for (protocol, port) -> rule_id,
 * but must stay synchronized with the actual rules map.
 */

#include "gtest/gtest.h"
#include "ebpf/ebpf_loader.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

using namespace nids;

// Rule index key structure: (protocol << 16) | port
struct rule_index_key {
    uint32_t proto_port;  /* (protocol << 16) | port */
};

// Simulated rule entry matching BPF struct
struct rule_entry {
    uint32_t rule_id;
    uint8_t action;
    uint8_t severity;
    uint8_t protocol;
    uint16_t dst_port;
    uint16_t dst_port_max;
    uint8_t dpi_needed;
    uint8_t padding[2];
};

// Helper to create rule_index key
static inline uint32_t make_proto_port_key(uint8_t proto, uint16_t port) {
    return (static_cast<uint32_t>(proto) << 16) | port;
}

// Helper to check port range match
static inline bool port_match(uint16_t rule_port, uint16_t rule_port_max, uint16_t dst_port) {
    if (rule_port_max == 0) {
        // Single port
        return rule_port == dst_port;
    } else {
        // Port range
        return dst_port >= rule_port && dst_port <= rule_port_max;
    }
}

class RuleIndexConsistencyTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Simulated rules map: rule_id -> rule_entry
    std::unordered_map<uint32_t, rule_entry> rules_map;

    // Simulated rule_index map: proto_port -> rule_id
    std::unordered_map<uint32_t, uint32_t> rule_index_map;

    // Add rule and update index
    void add_rule(const rule_entry& rule) {
        rules_map[rule.rule_id] = rule;

        // Only index single-port rules (not ranges)
        if (rule.dst_port_max == 0) {
            uint32_t key = make_proto_port_key(rule.protocol, rule.dst_port);
            rule_index_map[key] = rule.rule_id;
        }
    }

    // Delete rule and update index
    void delete_rule(uint32_t rule_id) {
        auto it = rules_map.find(rule_id);
        if (it != rules_map.end()) {
            const rule_entry& rule = it->second;

            // Only remove from index if it was indexed
            if (rule.dst_port_max == 0) {
                uint32_t key = make_proto_port_key(rule.protocol, rule.dst_port);
                rule_index_map.erase(key);
            }
            rules_map.erase(it);
        }
    }

    // Look up rule via index
    rule_entry* lookup_via_index(uint8_t proto, uint16_t port) {
        uint32_t key = make_proto_port_key(proto, port);
        auto idx_it = rule_index_map.find(key);
        if (idx_it != rule_index_map.end()) {
            auto rule_it = rules_map.find(idx_it->second);
            if (rule_it != rules_map.end()) {
                return &rule_it->second;
            }
            // Index points to deleted rule - invalidate index
            rule_index_map.erase(idx_it);
        }
        return nullptr;
    }
};

// T-14: rule_index key is correctly formed
TEST_F(RuleIndexConsistencyTest, IndexKeyFormation) {
    // TCP port 80: (6 << 16) | 80 = 393216 | 80 = 393296
    uint32_t key = make_proto_port_key(6, 80);
    EXPECT_EQ(key, 393296u);

    // UDP port 53: (17 << 16) | 53 = 1114112 | 53 = 1114165
    key = make_proto_port_key(17, 53);
    EXPECT_EQ(key, 1114165u);

    // Any protocol (0) port  any: (0 << 16) | 0 = 0
    key = make_proto_port_key(0, 0);
    EXPECT_EQ(key, 0u);
}

// T-14: Index and rules map stay in sync after adding rules
TEST_F(RuleIndexConsistencyTest, SyncAfterAddRule) {
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    rule_entry rule2 = {2, 2, 3, 17, 53, 0, 0, {0, 0}};

    add_rule(rule1);
    add_rule(rule2);

    // Rules map has both
    EXPECT_EQ(rules_map.size(), 2u);
    EXPECT_NE(rules_map.find(1), rules_map.end());
    EXPECT_NE(rules_map.find(2), rules_map.end());

    // Index has both
    EXPECT_EQ(rule_index_map.size(), 2u);
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 1u);
    EXPECT_EQ(rule_index_map[make_proto_port_key(17, 53)], 2u);
}

// T-14: Index and rules map stay in sync after deleting rule
TEST_F(RuleIndexConsistencyTest, SyncAfterDeleteRule) {
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    rule_entry rule2 = {2, 2, 3, 17, 53, 0, 0, {0, 0}};

    add_rule(rule1);
    add_rule(rule2);

    // Delete rule1
    delete_rule(1);

    // Rules map only has rule2
    EXPECT_EQ(rules_map.size(), 1u);
    EXPECT_EQ(rules_map.find(1), rules_map.end());
    EXPECT_NE(rules_map.find(2), rules_map.end());

    // Index only has rule2
    EXPECT_EQ(rule_index_map.size(), 1u);
    EXPECT_EQ(rule_index_map.find(make_proto_port_key(6, 80)), rule_index_map.end());
    EXPECT_EQ(rule_index_map[make_proto_port_key(17, 53)], 2u);
}

// T-14: Index lookup returns correct rule
TEST_F(RuleIndexConsistencyTest, IndexLookupReturnsCorrectRule) {
    rule_entry rule1 = {100, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Look up TCP:80
    rule_entry* found = lookup_via_index(6, 80);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->rule_id, 100u);
    EXPECT_EQ(found->protocol, 6u);
    EXPECT_EQ(found->dst_port, 80u);
}

// T-14: Index lookup returns nullptr for non-existent rule
TEST_F(RuleIndexConsistencyTest, IndexLookupNotFound) {
    // No rules added

    // Look up TCP:80
    rule_entry* found = lookup_via_index(6, 80);
    EXPECT_EQ(found, nullptr);

    // Look up UDP:53
    found = lookup_via_index(17, 53);
    EXPECT_EQ(found, nullptr);
}

// T-14: Index invalidated when rule is deleted
TEST_F(RuleIndexConsistencyTest, IndexInvalidatedOnDelete) {
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Verify exists
    EXPECT_NE(lookup_via_index(6, 80), nullptr);

    // Delete rule
    delete_rule(1);

    // Index should not have the entry
    EXPECT_EQ(rule_index_map.find(make_proto_port_key(6, 80)), rule_index_map.end());

    // Lookup should fail
    EXPECT_EQ(lookup_via_index(6, 80), nullptr);
}

// T-14: Index not created for port range rules
TEST_F(RuleIndexConsistencyTest, NoIndexForRangeRules) {
    // Single port rule - indexed
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Range rule - not indexed
    rule_entry rule2 = {2, 2, 3, 6, 80, 8080, 0, {0, 0}};
    add_rule(rule2);

    // Only rule1 should be in index
    EXPECT_EQ(rule_index_map.size(), 1u);
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 1u);
}

// T-14: Same proto:port can have only one rule in index
TEST_F(RuleIndexConsistencyTest, OneRulePerProtoPort) {
    // First rule for TCP:80
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Second rule for TCP:80 - overwrites
    rule_entry rule2 = {2, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule2);

    // Index points to newer rule
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 2u);

    // Both rules still in rules map (for linear scan fallback)
    EXPECT_EQ(rules_map.size(), 2u);
}

// T-14: Different protocols for same port are separate
TEST_F(RuleIndexConsistencyTest, DifferentProtocolsSeparate) {
    rule_entry tcp_rule = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    rule_entry udp_rule = {2, 2, 3, 17, 80, 0, 0, {0, 0}};

    add_rule(tcp_rule);
    add_rule(udp_rule);

    // Both indexed separately
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 1u);   // TCP
    EXPECT_EQ(rule_index_map[make_proto_port_key(17, 80)], 2u); // UDP
}

// T-14: Index fallback to linear scan for non-indexed rules
TEST_F(RuleIndexConsistencyTest, FallbackToLinearScan) {
    // Add a range rule
    rule_entry range_rule = {1, 2, 3, 6, 80, 8080, 0, {0, 0}};
    add_rule(range_rule);

    // Index lookup should fail (range rules not indexed)
    EXPECT_EQ(lookup_via_index(6, 80), nullptr);

    // But linear scan should find it
    // This simulates what the BPF code does - falls back to linear scan
    bool found = false;
    for (const auto& pair : rules_map) {
        const rule_entry& rule = pair.second;
        if (rule.protocol == 0 || rule.protocol == 6) {
            if (port_match(rule.dst_port, rule.dst_port_max, 80)) {
                found = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found);
}

// T-14: Index rebuild scenario
TEST_F(RuleIndexConsistencyTest, IndexRebuildScenario) {
    // Simulate adding many rules then deleting some
    for (uint32_t i = 1; i <= 100; i++) {
        rule_entry rule = {i, 2, 3, 6, static_cast<uint16_t>(80 + i), 0, 0, {0, 0}};
        add_rule(rule);
    }

    EXPECT_EQ(rule_index_map.size(), 100u);
    EXPECT_EQ(rules_map.size(), 100u);

    // Delete every other rule
    for (uint32_t i = 1; i <= 100; i += 2) {
        delete_rule(i);
    }

    EXPECT_EQ(rule_index_map.size(), 50u);
    EXPECT_EQ(rules_map.size(), 50u);

    // Verify remaining rules are still correctly indexed
    for (uint32_t i = 2; i <= 100; i += 2) {
        uint32_t expected_key = make_proto_port_key(6, static_cast<uint16_t>(80 + i));
        EXPECT_EQ(rule_index_map[expected_key], i);
    }
}

// T-14: rule_index_key structure size
TEST_F(RuleIndexConsistencyTest, IndexKeyStructureSize) {
    rule_index_key key = {};
    key.proto_port = make_proto_port_key(6, 80);

    EXPECT_EQ(key.proto_port, 393296u);
    EXPECT_EQ(sizeof(rule_index_key), 4u);
}

// T-14: rule_entry structure size
TEST_F(RuleIndexConsistencyTest, RuleEntryStructureSize) {
    rule_entry entry = {};
    entry.rule_id = 1;
    entry.action = 2;
    entry.severity = 3;
    entry.protocol = 6;
    entry.dst_port = 80;
    entry.dst_port_max = 0;
    entry.dpi_needed = 0;

    // BPF struct is aligned to 8-byte boundary: 4+1+1+1+(padding)+2+2+1+2 = 16 bytes
    // Userspace RuleEntry uses __attribute__((packed)) to be 14 bytes
    EXPECT_EQ(sizeof(rule_entry), 16u);
}

// T-14: Protocol value encoding
TEST_F(RuleIndexConsistencyTest, ProtocolEncoding) {
    // Protocol values from nids_common.h / etc.
    EXPECT_EQ(make_proto_port_key(6, 80), (6 << 16) | 80);   // TCP
    EXPECT_EQ(make_proto_port_key(17, 53), (17 << 16) | 53); // UDP
    EXPECT_EQ(make_proto_port_key(1, 0), (1 << 16) | 0);     // ICMP
    EXPECT_EQ(make_proto_port_key(0, 0), 0u);                // Any
}

// T-14: Port match for single port
TEST_F(RuleIndexConsistencyTest, PortMatchSinglePort) {
    // Single port rule
    EXPECT_TRUE(port_match(80, 0, 80));    // Exact match
    EXPECT_FALSE(port_match(80, 0, 81));   // Different port
    EXPECT_FALSE(port_match(80, 0, 8080)); // Range port
}

// T-14: Port match for port range
TEST_F(RuleIndexConsistencyTest, PortMatchRange) {
    // Range rule: 80-8080
    EXPECT_TRUE(port_match(80, 8080, 80));     // Start of range
    EXPECT_TRUE(port_match(80, 8080, 8080));    // End of range
    EXPECT_TRUE(port_match(80, 8080, 443));     // Middle of range
    EXPECT_FALSE(port_match(80, 8080, 79));    // Below range
    EXPECT_FALSE(port_match(80, 8080, 8081)); // Above range
}

// T-14: Concurrent add/delete consistency
TEST_F(RuleIndexConsistencyTest, ConcurrentAddDelete) {
    // Add rule
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Verify exists
    EXPECT_NE(lookup_via_index(6, 80), nullptr);

    // Simulate concurrent delete and re-add
    // (In real system, index might be temporarily inconsistent)
    delete_rule(1);
    EXPECT_EQ(lookup_via_index(6, 80), nullptr);

    // Re-add same rule
    add_rule(rule1);
    EXPECT_NE(lookup_via_index(6, 80), nullptr);
}

// T-14: Empty rules map handling
TEST_F(RuleIndexConsistencyTest, EmptyRulesMap) {
    EXPECT_EQ(rules_map.size(), 0u);
    EXPECT_EQ(rule_index_map.size(), 0u);

    // Lookups should fail
    EXPECT_EQ(lookup_via_index(6, 80), nullptr);
    EXPECT_EQ(lookup_via_index(17, 53), nullptr);
}

// T-14: Index maintenance after rule update
TEST_F(RuleIndexConsistencyTest, IndexUpdateScenario) {
    rule_entry rule1 = {1, 2, 3, 6, 80, 0, 0, {0, 0}};
    add_rule(rule1);

    // Index points to rule1
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 1u);

    // Simulate updating rule1's port (this would require re-indexing)
    // In practice, delete + re-add
    delete_rule(1);
    rule1.dst_port = 443;
    add_rule(rule1);

    // Index now points to new port
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 0u); // No longer indexed
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 443)], 1u);
}

// T-14: DPI-needed rules are indexed
TEST_F(RuleIndexConsistencyTest, DpiNeededRulesIndexed) {
    // DPI rule for content matching
    rule_entry dpi_rule = {1, 2, 3, 6, 80, 0, 1, {0, 0}};
    add_rule(dpi_rule);

    // Should still be indexed (for fast proto/port pre-filter)
    EXPECT_EQ(rule_index_map[make_proto_port_key(6, 80)], 1u);

    // Look up returns the rule
    rule_entry* found = lookup_via_index(6, 80);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->dpi_needed, 1u);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
