#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <string>
#include <string_view>
#include <algorithm>
#include <cstring>
#include <stdexcept>

// protocol constants
constexpr std::size_t USER_PASS_FIELD   = 32;
constexpr std::size_t PROTO_HEADER_SIZE = 4;  // BE16 total size + type + seq

// message types (both enum and legacy constants for convenience)
enum class MsgType : uint8_t { LoginReq = 0, LoginResp = 1, EchoReq = 2, EchoResp = 3 };
constexpr uint8_t MSG_LOGIN_REQ  = static_cast<uint8_t>(MsgType::LoginReq);
constexpr uint8_t MSG_LOGIN_RESP = static_cast<uint8_t>(MsgType::LoginResp);
constexpr uint8_t MSG_ECHO_REQ   = static_cast<uint8_t>(MsgType::EchoReq);
constexpr uint8_t MSG_ECHO_RESP  = static_cast<uint8_t>(MsgType::EchoResp);

// BE16 helpers
inline uint16_t be16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>( (uint16_t(p[0]) << 8) | uint16_t(p[1]) );
}
inline void put_be16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[1] = static_cast<uint8_t>( v       & 0xFF);
}

/** Parse a 32-byte ASCIIZ field from payload at offset
 *  Returns empty if OOB
 * */
[[nodiscard]] inline std::string parse_asciiz32(std::span<const uint8_t> payload, std::size_t offset) noexcept {
    if (offset >= payload.size())
        return {};

    const std::size_t end = std::min(offset + USER_PASS_FIELD, payload.size());
    std::string out; out.reserve(USER_PASS_FIELD);
    for (std::size_t i = offset; i < end; ++i) {
        const uint8_t b = payload[i];
        if (b == 0)
            break;
        out.push_back(static_cast<char>(b));
    }
    return out;
}

// Write ASCIIZ
inline void write_asciiz32(std::span<uint8_t, USER_PASS_FIELD> out, std::string_view s) noexcept {
    const std::size_t n = std::min<std::size_t>(s.size(), USER_PASS_FIELD - 1);
    if (n)
        std::memcpy(out.data(), s.data(), n);
    if (n < USER_PASS_FIELD)
        std::memset(out.data() + n, 0, USER_PASS_FIELD - n);
}

/** Build a complete frame --- [BE16 size][type][seq][payload] ---
 * Throws std::runtime_error if total > 0xFFFF
 */
inline std::vector<uint8_t> build_frame(uint8_t type, uint8_t seq, std::span<const uint8_t> payload) {
    const std::size_t total = PROTO_HEADER_SIZE + payload.size();
    if (total > 0xFFFF)
        throw std::runtime_error("frame too large for 16-bit length");
    std::vector<uint8_t> out(total);
    put_be16(out.data(), static_cast<uint16_t>(total));
    out[2] = type;
    out[3] = seq;
    if (!payload.empty())
        std::memcpy(out.data() + PROTO_HEADER_SIZE, payload.data(), payload.size());
    return out;
}

// Seed = (seq << 16) | (user_sum << 8) | pass_sum
inline uint32_t compute_seed(uint8_t seq, uint8_t user_sum, uint8_t pass_sum) noexcept {
    return (uint32_t(seq) << 16) | (uint32_t(user_sum) << 8) | uint32_t(pass_sum);
}
