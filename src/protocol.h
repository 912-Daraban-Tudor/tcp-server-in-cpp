#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>

// Message types
constexpr uint8_t MSG_LOGIN_REQ   = 0;  // Login Request
constexpr uint8_t MSG_LOGIN_RESP  = 1;  // Login Response
constexpr uint8_t MSG_ECHO_REQ    = 2;  // Echo Request
constexpr uint8_t MSG_ECHO_RESP   = 3;  // Echo Response

// Fixed ASCIIZ field sizes
constexpr size_t USER_PASS_FIELD = 32;

// Parse 32-byte ASCIIZ starting at 'offset'
inline std::string parse_asciiz32(const std::vector<uint8_t>& payload, size_t offset) {
    size_t end = std::min(offset + USER_PASS_FIELD, payload.size());
    std::string s; s.reserve(USER_PASS_FIELD);
    for (size_t i = offset; i < end; ++i) {
        if (payload[i] == 0) break;
        s.push_back(char(payload[i]));
    }
    return s;
}

// Big-endian 16-bit helpers (used for Echo length fields)
inline uint16_t be16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
inline void put_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}
