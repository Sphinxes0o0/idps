// SPDX-License-Identifier: MIT
/*
 * nids_bpf_proto.c - Protocol detection functions
 *
 * Extracted from nids_bpf.c for better code organization.
 * These functions detect application-layer protocols from packet payloads.
 */

#include "nids_common.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Check if payload starts with HTTP/ (HTTP response/request line)
 */
static __always_inline int check_http(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 5) return 0;
    /* Boyer-Moore-Horspool style: check "HTTP/" at start */
    if (payload[0] == 'H' && payload[1] == 'T' && payload[2] == 'T' && payload[3] == 'P' && payload[4] == '/') return 1;
    return 0;
}

/*
 * Check if payload starts with "SSH-" (SSH protocol banner)
 */
static __always_inline int check_ssh(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    if (payload[0] == 'S' && payload[1] == 'S' && payload[2] == 'H' && payload[3] == '-') return 1;
    return 0;
}

/*
 * Check for FTP command (3 uppercase letters followed by space or \r)
 * Common FTP commands: USER, PASS, LIST, RETR, STOR, CWD, PWD, QUIT, PORT, PASV, etc.
 */
static __always_inline int check_ftp(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    /* Check if first 3 bytes are ASCII letters (case-insensitive, per RFC 959) */
    __u8 b0 = payload[0];
    __u8 b1 = payload[1];
    __u8 b2 = payload[2];
    /* Convert lowercase to uppercase for case-insensitive matching */
    if (b0 >= 'a' && b0 <= 'z') b0 = b0 - 'a' + 'A';
    if (b1 >= 'a' && b1 <= 'z') b1 = b1 - 'a' + 'A';
    if (b2 >= 'a' && b2 <= 'z') b2 = b2 - 'a' + 'A';
    if (b0 >= 'A' && b0 <= 'Z' &&
        b1 >= 'A' && b1 <= 'Z' &&
        b2 >= 'A' && b2 <= 'Z') return 1;
    return 0;
}

/*
 * Check for Telnet option negotiation (IAC = 0xFF followed by command byte)
 */
static __always_inline int check_telnet(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 2) return 0;
    if (payload[0] == 0xFF && payload[1] >= 0xF0) return 1; /* IAC + command (WILL/WONT/DO/DONT) */
    return 0;
}

/*
 * Check for SMTP banner (220 response code)
 */
static __always_inline int check_smtp(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    return (payload[0] == '2' && payload[1] == '2' && payload[2] == '0' &&
           (payload[3] == ' ' || payload[3] == '-'));
}

/*
 * Check for POP3 response (+OK or -ERR)
 */
static __always_inline int check_pop3(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    if (payload[0] == '+' && payload[1] == 'O' && payload[2] == 'K') return 1;
    if (payload[0] == '-' && payload[1] == 'E' && payload[2] == 'R' && payload[3] == 'R') return 1;
    return 0;
}

/*
 * Check for IMAP response (* OK)
 */
static __always_inline int check_imap(const __u8 *payload, __u32 payload_len) {
    if (payload_len < 4) return 0;
    return (payload[0] == '*' && payload[1] == ' ' && payload[2] == 'O' && payload[3] == 'K');
}
