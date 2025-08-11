#pragma once
#include <cstdint>
#include <vector>
#include <string_view>

constexpr uint32_t LCG_A = 1103515245u;
constexpr uint32_t LCG_C = 12345u;
constexpr uint32_t LCG_M = 0x7FFFFFFFu;

// Sum mod 256 over raw bytes
inline uint8_t checksum8_bytes(const uint8_t* p, size_t n) {
    uint8_t s = 0;
    for (size_t i = 0; i < n; ++i) s = static_cast<uint8_t>(s + p[i]);
    return s;
}

// Sum mod 256 over ASCII string (view == no copy)
inline uint8_t checksum8_str_ascii(std::string_view s) {
    return checksum8_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// LCG step: (key*A+C) % M with 32-bit wrap before mod
inline uint32_t lcg_next(uint32_t key) {
    uint32_t tmp = key * LCG_A + LCG_C;   // wraps in 32-bit
    return tmp % LCG_M;
}

// XOR buffer in place with LCG keystream derived from seed, with no allocations
inline void xor_with_lcg_inplace(uint32_t seed, uint8_t* data, size_t n) {
    if (n == 0) return;
    uint32_t k = lcg_next(seed);
    data[0] ^= static_cast<uint8_t>(k % 256);
    for (size_t i = 1; i < n; ++i) {
        k = lcg_next(k);
        data[i] ^= static_cast<uint8_t>(k % 256);
    }
}

// vector overload
inline void xor_with_lcg(uint32_t seed, std::vector<uint8_t>& buf) {
    if (!buf.empty()) xor_with_lcg_inplace(seed, buf.data(), buf.size());
}
