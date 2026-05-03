/* SPDX-License-Identifier: MIT */
/*
 * test_tcp_flags.cpp - T-04: TCP flag 组合测试
 *
 * 测试 SYN+ACK、FIN+ACK 等非法组合的处理
 */

// TCP flag definitions (from linux/tcp.h or similar)
#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_PSH  0x08
#define TCP_FLAG_ACK  0x10
#define TCP_FLAG_URG  0x20
#define TCP_FLAG_ECE  0x40
#define TCP_FLAG_CWR  0x80

#include <gtest/gtest.h>
#include <cstdint>

class TcpFlagTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to check if flag combination is valid
    static bool is_valid_tcp_flag_combination(uint8_t flags) {
        // Invalid combinations:
        // 1. SYN+FIN (both trying to start and end connection)
        // 2. SYN+RST (cannot start and reset at same time)
        // 3. NULL scan: no flags set (0x00)
        // 4. XMAS scan: FIN+URG+PSH set, no ACK

        // Valid combinations:
        // - SYN (connection start)
        // - SYN+ACK (connection start response)
        // - ACK (acknowledgment)
        // - FIN (connection end request from one side)
        // - FIN+ACK
        // - RST (connection reset)
        // - RST+ACK
        // - PSH+ACK (data push)
        // - PSH+ACK+URG

        // NULL scan: no flags (0x00)
        if (flags == 0x00) {
            return false;  // NULL scan detected
        }

        // XMAS scan: FIN+URG+PSH ALL set, no ACK
        // Must have FIN, URG, and PSH all set, AND no ACK
        if ((flags & (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) == (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH) &&
            !(flags & TCP_FLAG_ACK)) {
            return false;  // XMAS scan detected
        }

        // SYN+FIN is invalid (cannot both start and end connection)
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_FIN)) {
            return false;
        }

        // SYN+RST is invalid (cannot both start and reset connection)
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_RST)) {
            return false;
        }

        return true;
    }

    // Helper to identify scan types
    static const char* identify_scan_type(uint8_t flags) {
        if (flags == 0x00) return "NULL";
        if ((flags & (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) == (TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH)) {
            return "XMAS";
        }
        if ((flags & TCP_FLAG_SYN) && !(flags & ~TCP_FLAG_SYN)) {
            return "SYN";
        }
        if ((flags & TCP_FLAG_FIN) && !(flags & ~TCP_FLAG_FIN)) {
            return "FIN";
        }
        if ((flags & TCP_FLAG_SYN) && (flags & TCP_FLAG_ACK)) {
            return "SYN-ACK";
        }
        if ((flags & TCP_FLAG_RST) && !(flags & ~TCP_FLAG_RST)) {
            return "RST";
        }
        if ((flags & TCP_FLAG_RST) && (flags & TCP_FLAG_ACK)) {
            return "RST-ACK";
        }
        if ((flags & TCP_FLAG_FIN) && (flags & TCP_FLAG_ACK)) {
            return "FIN-ACK";
        }
        return "OTHER";
    }
};

// T-04: Valid TCP flag combinations
TEST_F(TcpFlagTest, ValidCombinations) {
    // SYN - connection start
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_SYN));

    // SYN+ACK - connection response
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_SYN | TCP_FLAG_ACK));

    // ACK - acknowledgment only
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_ACK));

    // FIN - connection end from one side
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_FIN));

    // FIN+ACK - connection end with ack
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_FIN | TCP_FLAG_ACK));

    // RST - reset connection
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_RST));

    // RST+ACK - reset with acknowledgment
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_RST | TCP_FLAG_ACK));

    // PSH+ACK - data push
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_PSH | TCP_FLAG_ACK));

    // PSH+ACK+URG
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_PSH | TCP_FLAG_ACK | TCP_FLAG_URG));
}

// T-04: Invalid TCP flag combinations - SYN+FIN
TEST_F(TcpFlagTest, InvalidSynFin) {
    // SYN+FIN is invalid - cannot both start and end connection
    uint8_t syn_fin = TCP_FLAG_SYN | TCP_FLAG_FIN;
    EXPECT_FALSE(is_valid_tcp_flag_combination(syn_fin));
}

// T-04: Invalid TCP flag combinations - SYN+FIN+ACK
TEST_F(TcpFlagTest, InvalidSynFinAck) {
    // SYN+FIN+ACK is invalid
    uint8_t syn_fin_ack = TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_ACK;
    EXPECT_FALSE(is_valid_tcp_flag_combination(syn_fin_ack));
}

// T-04: Invalid TCP flag combinations - NULL scan (no flags)
TEST_F(TcpFlagTest, InvalidNullScan) {
    // NULL scan - no flags set
    EXPECT_FALSE(is_valid_tcp_flag_combination(0x00));
}

// T-04: Invalid TCP flag combinations - XMAS scan
TEST_F(TcpFlagTest, InvalidXmasScan) {
    // XMAS scan: FIN+URG+PSH (no ACK)
    uint8_t xmas = TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH;
    EXPECT_FALSE(is_valid_tcp_flag_combination(xmas));
}

// T-04: Invalid SYN+RST combination
TEST_F(TcpFlagTest, InvalidSynRst) {
    // SYN+RST - cannot both be in same packet
    uint8_t syn_rst = TCP_FLAG_SYN | TCP_FLAG_RST;
    EXPECT_FALSE(is_valid_tcp_flag_combination(syn_rst));
}

// T-04: Scan type identification - SYN scan
TEST_F(TcpFlagTest, IdentifySynScan) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_SYN), "SYN");
}

// T-04: Scan type identification - SYN-ACK
TEST_F(TcpFlagTest, IdentifySynAck) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_SYN | TCP_FLAG_ACK), "SYN-ACK");
}

// T-04: Scan type identification - NULL scan
TEST_F(TcpFlagTest, IdentifyNullScan) {
    EXPECT_STREQ(identify_scan_type(0x00), "NULL");
}

// T-04: Scan type identification - XMAS scan
TEST_F(TcpFlagTest, IdentifyXmasScan) {
    uint8_t xmas = TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH;
    EXPECT_STREQ(identify_scan_type(xmas), "XMAS");
}

// T-04: Scan type identification - FIN scan
TEST_F(TcpFlagTest, IdentifyFinScan) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_FIN), "FIN");
}

// T-04: Scan type identification - RST scan
TEST_F(TcpFlagTest, IdentifyRstScan) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_RST), "RST");
}

// T-04: Scan type identification - FIN-ACK
TEST_F(TcpFlagTest, IdentifyFinAck) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_FIN | TCP_FLAG_ACK), "FIN-ACK");
}

// T-04: Scan type identification - RST-ACK
TEST_F(TcpFlagTest, IdentifyRstAck) {
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_RST | TCP_FLAG_ACK), "RST-ACK");
}

// T-04: ACK-only is valid and not a scan
TEST_F(TcpFlagTest, AckOnlyValid) {
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_ACK));
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_ACK), "OTHER");
}

// T-04: PSH+ACK is valid (normal data packet)
TEST_F(TcpFlagTest, PshAckValid) {
    EXPECT_TRUE(is_valid_tcp_flag_combination(TCP_FLAG_PSH | TCP_FLAG_ACK));
}

// T-04: Full range scan type detection
TEST_F(TcpFlagTest, FullScanDetection) {
    // All scan types should be identified correctly
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_SYN), "SYN");
    EXPECT_STREQ(identify_scan_type(0x00), "NULL");
    EXPECT_STREQ(identify_scan_type(TCP_FLAG_FIN | TCP_FLAG_URG | TCP_FLAG_PSH), "XMAS");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}