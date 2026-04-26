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

    return 0;
}

// 从输入流中提取下一个带引号的字符串
// 处理引号内包含空格的情况
bool parse_quoted_string(std::istringstream& iss, std::string& result) {
    char c;
    // 跳过空白
    while (iss.get(c) && std::isspace(c)) {}
    if (!iss || c != '"') {
        if (iss) iss.putback(c);
        return false;
    }

    // 读取引号内的内容
    result.clear();
    while (iss.get(c)) {
        if (c == '"') {
            // 检查是否是转义的引号
            if (iss.peek() == '"') {
                iss.get(); // 读取下一个 "
                result += '"';
            } else {
                // 正常的引号结束
                return true;
            }
        } else {
            result += c;
        }
    }
    return false; // 引号未正确关闭
}

} // anonymous namespace

bool RuleParser::parse_line(const std::string& line, MatchRule& rule) {
    // 跳过注释和空行
    std::string trimmed = trim(line);
    if (trimmed.empty() || trimmed[0] == '#')
        return false;

    std::istringstream iss(trimmed);
    std::string token;

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

    // 3. 读取 dst_port (支持范围格式: "80:90" 表示 80-90)
    if (!(iss >> token)) {
        error_ = "missing dst_port";
        return false;
    }
    if (token == "any" || token == "0") {
        rule.dst_port = 0;
        rule.dst_port_max = 0;
    } else {
        // 检查是否有范围分隔符 ":"
        size_t colon_pos = token.find(':');
        if (colon_pos != std::string::npos) {
            // 端口范围格式: "80:90"
            try {
                rule.dst_port = static_cast<uint16_t>(std::stoi(token.substr(0, colon_pos)));
                rule.dst_port_max = static_cast<uint16_t>(std::stoi(token.substr(colon_pos + 1)));
            } catch (...) {
                error_ = "invalid dst_port range: " + token;
                return false;
            }
            if (rule.dst_port_max < rule.dst_port) {
                error_ = "invalid port range (max < min): " + token;
                return false;
            }
        } else {
            // 单端口格式
            try {
                rule.dst_port = static_cast<uint16_t>(std::stoi(token));
                rule.dst_port_max = 0;
            } catch (...) {
                error_ = "invalid dst_port: " + token;
                return false;
            }
        }
    }

    // 4. 读取 content (带引号)
    if (!parse_quoted_string(iss, rule.content)) {
        error_ = "invalid content format";
        return false;
    }

    // 5. 读取 message (带引号)
    if (!parse_quoted_string(iss, rule.message)) {
        error_ = "invalid message format";
        return false;
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
