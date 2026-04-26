/* SPDX-License-Identifier: MIT */
/*
 * rule_parser.h - 规则文件解析器
 *
 * 支持类似 Snort 的规则格式:
 *   <id> <proto> <dst_port> "<content>" "<message>"
 *
 * 规则分类:
 *   - 简单规则 (content=""): 只匹配 proto+port，推送到 eBPF 内核
 *   - 内容规则 (content!=""): 需要 BMH 内容匹配，在用户态处理
 */

#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace nids {

/**
 * @brief 单条匹配规则
 */
struct MatchRule {
    int         id       = 0;
    std::string message;
    std::string content;     ///< 原始内容字符串（空=匹配所有）
    uint8_t     proto    = 0;   ///< 6=TCP, 17=UDP, 0=any
    uint16_t    dst_port = 0;   ///< 起始端口（0=any）
    uint16_t    dst_port_max = 0; ///< 范围结束端口（0=单端口）
    bool        need_dpi = false; ///< 是否需要深度内容检查
};

/**
 * @brief 解析后的规则集
 */
struct RuleSet {
    std::vector<MatchRule> simple_rules;  ///< 简单规则（推送到内核）
    std::vector<MatchRule> content_rules;  ///< 内容规则（用户态 BMH）
};

/**
 * @brief 规则文件解析器
 */
class RuleParser {
public:
    RuleParser() = default;

    /**
     * @brief 解析规则文件
     * @param path 规则文件路径
     * @return 解析后的规则集，失败时返回空
     */
    RuleSet parse_file(const std::string& path);

    /**
     * @brief 从字符串解析单行规则
     * @param line 规则行
     * @param rule 输出规则
     * @return true 成功
     */
    bool parse_line(const std::string& line, MatchRule& rule);

    /**
     * @brief 获取解析错误信息
     */
    const std::string& error() const { return error_; }

private:
    std::string error_;
};

} // namespace nids
