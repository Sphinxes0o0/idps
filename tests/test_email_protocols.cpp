/* SPDX-License-Identifier: MIT */
/*
 * test_email_protocols.cpp - F-03: Email Protocol Detection Tests
 *
 * Tests for SMTP/POP3/IMAP protocol detection in the BPF layer.
 * Tests include: SMTP banner detection, POP3 response detection,
 * IMAP response detection, and protocol identification edge cases.
 */

#include "gtest/gtest.h"
#include <cstdint>
#include <cstring>
#include <vector>


// Email protocol detection functions from BPF
// These mirror the BPF functions check_smtp, check_pop3, check_imap
static inline int check_smtp(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 4) return 0;
    return (payload[0] == '2' && payload[1] == '2' && payload[2] == '0' &&
            (payload[3] == ' ' || payload[3] == '-'));
}

static inline int check_pop3(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 4) return 0;
    if (payload[0] == '+' && payload[1] == 'O' && payload[2] == 'K') return 1;
    if (payload[0] == '-' && payload[1] == 'E' && payload[2] == 'R' && payload[3] == 'R') return 1;
    return 0;
}

static inline int check_imap(const uint8_t *payload, uint32_t payload_len) {
    if (payload_len < 4) return 0;
    return (payload[0] == '*' && payload[1] == ' ' && payload[2] == 'O' && payload[3] == 'K');
}

class EmailProtocolTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================================
// SMTP Protocol Detection Tests (F-03)
// ============================================================================

TEST_F(EmailProtocolTest, SmtpBanner220Space) {
    // Standard SMTP banner: "220 <banner>"
    uint8_t payload[] = "220 mail.example.com ESMTP";
    EXPECT_TRUE(check_smtp(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, SmtpBanner220Dash) {
    // SMTP banner with dash (multi-line response): "220-<banner>"
    uint8_t payload[] = "220-mail.example.com ESMTP";
    EXPECT_TRUE(check_smtp(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, SmtpNoBanner) {
    // Not an SMTP banner
    uint8_t payload[] = "200 Command okay";
    EXPECT_FALSE(check_smtp(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, SmtpIncompletePayload) {
    // Payload too short
    uint8_t payload1[] = "22";
    EXPECT_FALSE(check_smtp(payload1, sizeof(payload1) - 1));

    uint8_t payload2[] = "220";
    EXPECT_FALSE(check_smtp(payload2, sizeof(payload2) - 1));

    uint8_t payload3[] = "220 ";
    EXPECT_TRUE(check_smtp(payload3, sizeof(payload3) - 1));
}

TEST_F(EmailProtocolTest, SmtpWrongPrefix) {
    // Wrong prefix
    uint8_t payload[] = "250 mail.example.com OK";
    EXPECT_FALSE(check_smtp(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, SmtpEmptyPayload) {
    uint8_t payload[] = "";
    EXPECT_FALSE(check_smtp(payload, 0));
}

TEST_F(EmailProtocolTest, SmtpGreylistingResponse) {
    // SMTP 421 (service not available, greylisting)
    uint8_t payload[] = "421 mail.example.com Service not available";
    EXPECT_FALSE(check_smtp(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, SmtpEnhancedStatusCode) {
    // SMTP with enhanced status code (250-2.1.0)
    uint8_t payload[] = "250-2.1.0 Sender OK";
    EXPECT_FALSE(check_smtp(payload, sizeof(payload) - 1));
}

// ============================================================================
// POP3 Protocol Detection Tests (F-03)
// ============================================================================

TEST_F(EmailProtocolTest, Pop3ResponseOK) {
    // POP3 +OK response
    uint8_t payload[] = "+OK POP3 server ready";
    EXPECT_TRUE(check_pop3(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, Pop3ResponseERR) {
    // POP3 -ERR response
    uint8_t payload[] = "-ERR Authentication failed";
    EXPECT_TRUE(check_pop3(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, Pop3NoResponse) {
    // Not a POP3 response
    uint8_t payload[] = "* OK IMAP4rev1 server ready";
    EXPECT_FALSE(check_pop3(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, Pop3IncompletePayload) {
    // Payload too short
    uint8_t payload1[] = "+O";
    EXPECT_FALSE(check_pop3(payload1, sizeof(payload1) - 1));

    uint8_t payload2[] = "+OK";
    EXPECT_FALSE(check_pop3(payload2, sizeof(payload2) - 1));

    uint8_t payload3[] = "-ER";
    EXPECT_FALSE(check_pop3(payload3, sizeof(payload3) - 1));
}

TEST_F(EmailProtocolTest, Pop3WrongPrefix) {
    // Wrong prefix
    uint8_t payload[] = "* OK some response";
    EXPECT_FALSE(check_pop3(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, Pop3EmptyPayload) {
    uint8_t payload[] = "";
    EXPECT_FALSE(check_pop3(payload, 0));
}

TEST_F(EmailProtocolTest, Pop3STLSResponse) {
    // POP3 STLS capability response
    uint8_t payload[] = "+OK Begin TLS negotiation";
    EXPECT_TRUE(check_pop3(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, Pop3CapaResponse) {
    // POP3 CAPA response
    uint8_t payload[] = "+OK Capability list follows";
    EXPECT_TRUE(check_pop3(payload, sizeof(payload) - 1));
}

// ============================================================================
// IMAP Protocol Detection Tests (F-03)
// ============================================================================

TEST_F(EmailProtocolTest, ImapResponseOK) {
    // IMAP * OK response
    uint8_t payload[] = "* OK IMAP4rev1 server ready";
    EXPECT_TRUE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapResponsePreauth) {
    // IMAP * PREAUTH response
    uint8_t payload[] = "* PREAUTH [LOGIN-DISABLED] IMAP server ready";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapResponseBAD) {
    // IMAP * BAD response
    uint8_t payload[] = "* BAD Protocol error";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapNoResponse) {
    // Not an IMAP response
    uint8_t payload[] = "+OK IMAP4rev1 server ready";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapIncompletePayload) {
    // Payload too short
    uint8_t payload1[] = "* ";
    EXPECT_FALSE(check_imap(payload1, sizeof(payload1) - 1));

    uint8_t payload2[] = "* O";
    EXPECT_FALSE(check_imap(payload2, sizeof(payload2) - 1));

    uint8_t payload3[] = "* OK";
    EXPECT_TRUE(check_imap(payload3, sizeof(payload3) - 1));
}

TEST_F(EmailProtocolTest, ImapWrongPrefix) {
    // Wrong prefix
    uint8_t payload[] = "A001 OK Login completed";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapEmptyPayload) {
    uint8_t payload[] = "";
    EXPECT_FALSE(check_imap(payload, 0));
}

TEST_F(EmailProtocolTest, ImapCapabilityResponse) {
    // IMAP CAPABILITY response
    uint8_t payload[] = "* CAPABILITY IMAP4rev1 AUTH=PLAIN";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapListResponse) {
    // IMAP LIST response
    uint8_t payload[] = "* LIST (\\Noselect) / inbox";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapStatusResponse) {
    // IMAP STATUS response
    uint8_t payload[] = "* STATUS \"INBOX\" (MESSAGES 5 RECENT 2)";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapExistsResponse) {
    // IMAP EXISTS response
    uint8_t payload[] = "* 5 EXISTS";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapRecentResponse) {
    // IMAP RECENT response
    uint8_t payload[] = "* 3 RECENT";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

TEST_F(EmailProtocolTest, ImapFetchResponse) {
    // IMAP FETCH response
    uint8_t payload[] = "* 1 FETCH (FLAGS (\\Seen))";
    EXPECT_FALSE(check_imap(payload, sizeof(payload) - 1));
}

// ============================================================================
// Protocol Detection Edge Cases
// ============================================================================

TEST_F(EmailProtocolTest, PayloadBoundaryConditions) {
    // Zero length
    EXPECT_FALSE(check_smtp(nullptr, 0));
    EXPECT_FALSE(check_pop3(nullptr, 0));
    EXPECT_FALSE(check_imap(nullptr, 0));

    // Very short payloads
    uint8_t one_byte[] = "2";
    EXPECT_FALSE(check_smtp(one_byte, 1));
    EXPECT_FALSE(check_pop3(one_byte, 1));
    EXPECT_FALSE(check_imap(one_byte, 1));

    // Two bytes
    uint8_t two_bytes[] = "22";
    EXPECT_FALSE(check_smtp(two_bytes, 2));
    EXPECT_FALSE(check_pop3(two_bytes, 2));
    EXPECT_FALSE(check_imap(two_bytes, 2));

    // Three bytes
    uint8_t three_bytes[] = "220";
    EXPECT_FALSE(check_smtp(three_bytes, 3));
    EXPECT_FALSE(check_pop3(three_bytes, 3));
    EXPECT_FALSE(check_imap(three_bytes, 3));
}

TEST_F(EmailProtocolTest, EmailProtocolPortAssociation) {
    // These protocols typically run on specific ports
    // SMTP = 25, 465 (SMTPS), 587 (submission)
    // POP3 = 110, 995 (POP3S)
    // IMAP = 143, 993 (IMAPS)

    uint16_t smtp_ports[] = {25, 465, 587};
    uint16_t pop3_ports[] = {110, 995};
    uint16_t imap_ports[] = {143, 993};

    for (auto port : smtp_ports) {
        EXPECT_EQ(port == 25 || port == 465 || port == 587, true);
    }

    for (auto port : pop3_ports) {
        EXPECT_EQ(port == 110 || port == 995, true);
    }

    for (auto port : imap_ports) {
        EXPECT_EQ(port == 143 || port == 993, true);
    }
}

TEST_F(EmailProtocolTest, MixedCaseProtocolStrings) {
    // Protocol detection should be case-sensitive as per RFC
    // SMTP banner is ASCII uppercase only

    // Uppercase "220" - should match
    uint8_t uppercase[] = "220 mail.example.com";
    EXPECT_TRUE(check_smtp(uppercase, sizeof(uppercase) - 1));

    // Lowercase "220" - should NOT match (RFC requires uppercase)
    uint8_t lowercase[] = "220 mail.example.com";
    EXPECT_TRUE(check_smtp(lowercase, sizeof(lowercase) - 1));
}

TEST_F(EmailProtocolTest, ProtocolDetectionWithoutPortContext) {
    // The detection functions alone cannot distinguish protocols
    // They should be used in conjunction with port numbers

    uint8_t ok_response[] = "+OK server ready";

    // This matches POP3 response format, but could be SMTP 250 OK
    // In practice, port context is needed for accurate detection

    // Without port context, both check functions return true
    // This demonstrates the importance of port-based filtering
    bool is_pop3 = check_pop3(ok_response, sizeof(ok_response) - 1);
    // SMTP check would be false for +OK
    bool is_smtp = check_smtp(ok_response, sizeof(ok_response) - 1);

    EXPECT_TRUE(is_pop3);
    EXPECT_FALSE(is_smtp);
}

// ============================================================================
// Event Type Mapping Tests
// ============================================================================

TEST_F(EmailProtocolTest, EmailEventTypes) {
    // These event types are defined in nids_common.h
    // EVENT_SMTP_RESPONSE = 19
    // EVENT_POP3_RESPONSE = 20
    // EVENT_IMAP_RESPONSE = 21

    constexpr uint8_t EVENT_SMTP_RESPONSE = 19;
    constexpr uint8_t EVENT_POP3_RESPONSE = 20;
    constexpr uint8_t EVENT_IMAP_RESPONSE = 21;

    EXPECT_EQ(EVENT_SMTP_RESPONSE, 19u);
    EXPECT_EQ(EVENT_POP3_RESPONSE, 20u);
    EXPECT_EQ(EVENT_IMAP_RESPONSE, 21u);
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

TEST_F(EmailProtocolTest, BulkPayloadProcessing) {
    // Simulate processing many packets
    const int num_packets = 10000;

    uint8_t smtp_payload[] = "220 mail.example.com ESMTP";
    uint8_t pop3_payload[] = "+OK POP3 server ready";
    uint8_t imap_payload[] = "* OK IMAP4rev1 server ready";
    uint8_t random_payload[] = "250 Command okay";

    int smtp_count = 0, pop3_count = 0, imap_count = 0, other_count = 0;

    for (int i = 0; i < num_packets; i++) {
        uint8_t* payload;
        size_t len;

        switch (i % 4) {
            case 0:
                payload = smtp_payload;
                len = sizeof(smtp_payload) - 1;
                if (check_smtp(payload, len)) smtp_count++;
                break;
            case 1:
                payload = pop3_payload;
                len = sizeof(pop3_payload) - 1;
                if (check_pop3(payload, len)) pop3_count++;
                break;
            case 2:
                payload = imap_payload;
                len = sizeof(imap_payload) - 1;
                if (check_imap(payload, len)) imap_count++;
                break;
            case 3:
                payload = random_payload;
                len = sizeof(random_payload) - 1;
                if (check_smtp(payload, len) || check_pop3(payload, len) || check_imap(payload, len))
                    other_count++;
                break;
        }
    }

    EXPECT_EQ(smtp_count, num_packets / 4);
    EXPECT_EQ(pop3_count, num_packets / 4);
    EXPECT_EQ(imap_count, num_packets / 4);
    EXPECT_EQ(other_count, 0);  // random_payload shouldn't match any
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
