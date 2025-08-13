#pragma once
#include <cstdint>
#include <vector>
#include <string_view>
#include <span>

// lcg params
constexpr uint32_t LCG_A = 1103515245u;
constexpr uint32_t LCG_C = 12345u;
constexpr uint32_t LCG_M = 0x7FFFFFFFu; // 2^31 - 1

// sum mod 256 over raw bytes
inline uint8_t checksum8_bytes(const uint8_t* p, size_t n) noexcept {
    uint8_t s = 0;
    for (size_t i = 0; i < n; ++i)
        s = static_cast<uint8_t>(s + p[i]);
    return s;
}

// sum mod 256 over ASCII string
inline uint8_t checksum8_str_ascii(std::string_view s) noexcept {
    uint8_t sum = 0;
    for (unsigned char ch : s)
        sum = static_cast<uint8_t>(sum + ch);
    return sum;
}

// LCG step = (key*A + C) % M using 64-bit intermediate
inline uint32_t lcg_next(uint32_t key) noexcept {
    const uint64_t prod = static_cast<uint64_t>(key) * LCG_A + LCG_C;
    return static_cast<uint32_t>(prod % static_cast<uint64_t>(LCG_M));
}

// XOR buffer in place with LCG keystream derived from seed
inline void xor_with_lcg_inplace(uint32_t seed, uint8_t* data, size_t n) noexcept {
    for (size_t i = 0; i < n; ++i) {
        seed = lcg_next(seed);
        data[i] ^= static_cast<uint8_t>(seed & 0xFF);
    }
}

inline void xor_with_lcg(uint32_t seed, std::vector<uint8_t>& buf) noexcept {
    if (!buf.empty())
        xor_with_lcg_inplace(seed, buf.data(), buf.size());
}
