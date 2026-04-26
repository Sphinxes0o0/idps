/* SPDX-License-Identifier: MIT */
/*
 * rule_parser.cpp - 规则文件解析器实现
 */

#include "rule_parser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace nids {

namespace {

// 去除字符串首尾空白
std::string trim(const std::string& s) {
    auto start = std::find_if_not(s.begin(), s.end(), [](unsigned char c) {
        return std::isspace(c);
    });
    auto end = std::find_if_not(s.rbegin(), s.rend(), [](unsigned char c) {
        return std::isspace(c);
    }).base();

    if (start >= end)
        return "";

    return std::string(start, end);
}

// 解析协议字符串
uint8_t parse_protocol(const std::string& s) {
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "tcp" || lower == "6")
        return 6;
    if (lower == "udp" || lower == "17")
        return 17;
    if (lower == "icmp" || lower == "1")
        return 1;
    if (lower == "any" || lower == "0")
        return 0;

    return 0;  // 默认 any
}

} // anonymous namespace

bool RuleParser::parse_line(const std::string& line, MatchRule& rule) {
    std::istringstream iss(line);
    std::string token;

    // 跳过注释和空行
    std::string trimmed = trim(line);
    if (trimmed.empty() || trimmed[0] == '#')
        return false;

    // 解析格式: <id> <proto> <dst_port> "<content>" "<message>"
    // 1. 读取 id
    if (!(iss >> token))
        return false;
    try {
        rule.id = std::stoi(token);
    } catch (...) {
        error_ = "invalid rule id: " + token;
        return false;
    }

    // 2. 读取 proto
    if (!(iss >> token)) {
        error_ = "missing proto";
        return false;
    }
    rule.proto = parse_protocol(token);

    // 3. 读取 dst_port
    if (!(iss >> token)) {
        error_ = "missing dst_port";
        return false;
    }
    if (token == "any" || token == "0") {
        rule.dst_port = 0;
    } else {
        try {
            rule.dst_port = static_cast<uint16_t>(std::stoi(token));
        } catch (...) {
            error_ = "invalid dst_port: " + token;
            return false;
        }
    }

    // 4. 读取 content (带引号)
    if (!(iss >> token)) {
        error_ = "missing content";
        return false;
    }
    // content 应该是 "..." 格式
    if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
        rule.content = token.substr(1, token.size() - 2);
    } else if (token == "\"\"") {
        rule.content = "";
    } else {
        error_ = "content must be quoted: " + token;
        return false;
    }

    // 5. 读取 message (带引号)
    if (!(iss >> token)) {
        error_ = "missing message";
        return false;
    }
    if (token.size() >= 2 && token.front() == '"' && token.back() == '"') {
        rule.message = token.substr(1, token.size() - 2);
    } else {
        // 可能是没有引号的情况，读取剩余所有内容
        rule.message = token;
        std::string rest;
        while (iss >> rest) {
            rule.message += " " + rest;
        }
        // 去除可能的尾随引号
        if (!rule.message.empty() && rule.message.back() == '"') {
            rule.message.pop_back();
        }
    }

    // 判断是否需要 DPI
    rule.need_dpi = !rule.content.empty();

    return true;
}

RuleSet RuleParser::parse_file(const std::string& path) {
    RuleSet rs;
    std::ifstream file(path);

    if (!file.is_open()) {
        error_ = "cannot open file: " + path;
        return rs;
    }

    std::string line;
    int line_num = 0;

    while (std::getline(file, line)) {
        line_num++;
        MatchRule rule;

        if (parse_line(line, rule)) {
            if (rule.need_dpi) {
                rs.content_rules.push_back(rule);
            } else {
                rs.simple_rules.push_back(rule);
            }
        } else if (!trim(line).empty() && trim(line)[0] != '#') {
            // 非空非注释行解析失败
            error_ = "line " + std::to_string(line_num) + ": " + error_;
        }
    }

    return rs;
}

} // namespace nids
