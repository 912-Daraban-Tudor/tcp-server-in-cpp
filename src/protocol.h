#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>
#include <algorithm>
#include <span>

// ---- Protocol constants -------

// message types
constexpr uint8_t MSG_LOGIN_REQ  = 0;
constexpr uint8_t MSG_LOGIN_RESP = 1;
constexpr uint8_t MSG_ECHO_REQ   = 2;
constexpr uint8_t MSG_ECHO_RESP  = 3;

// fixed ASCIIZ field size for username/password
constexpr std::size_t USER_PASS_FIELD   = 32;

// fixed wire header size = BE16 size (includes header) + 1B type + 1B seq
constexpr std::size_t PROTO_HEADER_SIZE = 4;

// ---- Helpers -------------

// parse a 32-byte ASCIIZ field starting at offset
// accepts any contiguous byte buffer using std::span (vector, array, etc)
inline std::string parse_asciiz32(std::span<const uint8_t> payload, std::size_t offset) {
    if (offset >= payload.size()) return {};
    const std::size_t end = std::min(offset + USER_PASS_FIELD, payload.size());

    std::string s;
    s.reserve(USER_PASS_FIELD);

    for (std::size_t i = offset; i < end; ++i) {
        const uint8_t b = payload[i];
        if (b == 0) break;                   // stop at first NUL
        s.push_back(static_cast<char>(b));
    }
    return s;
}

// BE 16-bit helpers used for length fields

inline uint16_t be16(const uint8_t* p) noexcept {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

inline void put_be16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>(v & 0xFF);
}
