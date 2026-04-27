/* SPDX-License-Identifier: MIT */
/*
 * bmh_search.h - Boyer-Moore-Horspool 字符串搜索算法
 *
 * 高效的子字符串搜索算法，最坏情况 O(m*n)，平均 O(n)
 * 无外部依赖
 */

#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

namespace nids {

/**
 * @brief Boyer-Moore-Horspool 搜索
 *
 * @param text 文本缓冲区
 * @param text_len 文本长度
 * @param pattern 模式串
 * @param pat_len 模式长度
 * @return true 如果找到匹配
 */
inline bool bmh_search(const uint8_t* text, size_t text_len,
                       const uint8_t* pattern, size_t pat_len) {
    if (pat_len == 0 || text_len < pat_len)
        return false;

    // 坏字符跳转表 (256 个条目)
    uint32_t skip[256];
    for (size_t i = 0; i < 256; i++)
        skip[i] = pat_len;

    // 最后一个字符外的所有字符的跳转距离
    for (size_t i = 0; i < pat_len - 1; i++)
        skip[pattern[i]] = pat_len - 1 - i;

    // 搜索
    size_t pos = 0;
    while (pos <= text_len - pat_len) {
        int j = static_cast<int>(pat_len) - 1;

        // 从后往前比较
        while (j >= 0 && static_cast<size_t>(j) < pat_len && pattern[j] == text[pos + j])
            j--;

        if (j < 0) {
            // 所有字符都匹配了 (j 从 0 减到了 -1)
            return true;
        }

        // 坏字符跳转
        uint8_t c = text[pos + pat_len - 1];
        pos += skip[c];
    }

    return false;
}

/**
 * @brief 在字符串中搜索子串
 */
inline bool bmh_search(const char* text, size_t text_len,
                       const char* pattern, size_t pat_len) {
    return bmh_search(reinterpret_cast<const uint8_t*>(text), text_len,
                       reinterpret_cast<const uint8_t*>(pattern), pat_len);
}

/**
 * @brief 搜索整个数据包 payload
 *
 * @param payload 数据包 payload 指针
 * @param payload_len payload 长度
 * @param pattern 要搜索的字符串
 * @return true 如果找到
 */
inline bool search_payload(const uint8_t* payload, size_t payload_len,
                           const std::string& pattern) {
    if (pattern.empty())
        return true;  // 空模式匹配所有
    if (payload_len < pattern.size())
        return false;

    return bmh_search(payload, payload_len,
                      reinterpret_cast<const uint8_t*>(pattern.data()),
                      pattern.size());
}

} // namespace nids
