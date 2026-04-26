/*
 * fuzz_rule_parser.cpp - Fuzz test for rule parser
 *
 * Compiles with libFuzzer:
 * clang++ -fsanitize=fuzzer -fno-omit-frame-pointer -g -O1 \
 *   -I../src -I../bpf -I/usr/include/bpf \
 *   fuzz_rule_parser.cpp ../src/rules/rule_parser.cpp \
 *   -o fuzz_rule_parser -lfuzzer
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include "../src/rules/rule_parser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // Ensure null-terminated string for parser
    char* input = new char[size + 1];
    memcpy(input, data, size);
    input[size] = '\0';

    nids::RuleParser parser;
    nids::MatchRule rule;

    // Try parsing as a single line
    parser.parse_line(input, rule);

    // Check for errors (parser should not crash)
    (void)parser.error();

    delete[] input;
    return 0;
}