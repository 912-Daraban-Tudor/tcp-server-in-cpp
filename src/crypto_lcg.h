#pragma once
#include <cstdint>
#include <vector>
#include <string>

inline uint8_t checksum8_bytes(const uint8_t* p, size_t n) {
    uint8_t s = 0;
    for (size_t i = 0; i < n; ++i) s = uint8_t(s + p[i]); // wraps mod 256
    return s;
}

inline uint8_t checksum8_str_ascii(const std::string& s) {
    return checksum8_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

// LCG: key_{i+1} = (key_i * 1103515245 + 12345) % 0x7FFFFFFF, with 32-bit wrap before modulus
inline uint32_t lcg_next(uint32_t key) {
    uint32_t tmp = key * 1103515245u + 12345u; // wraps in 32-bit
    return tmp % 0x7FFFFFFFu;
}

// Generate keystream (first byte from next_key(seed) % 256)
inline void lcg_keystream(uint32_t seed, uint8_t* out, size_t n) {
    if (n == 0) return;
    uint32_t k = lcg_next(seed);
    out[0] = uint8_t(k % 256);
    for (size_t i = 1; i < n; ++i) {
        k = lcg_next(k);
        out[i] = uint8_t(k % 256);
    }
}

// XOR buffer in-place with LCG keystream derived from seed
inline void xor_with_lcg(uint32_t seed, std::vector<uint8_t>& buf) {
    if (buf.empty()) return;
    std::vector<uint8_t> ks(buf.size());
    lcg_keystream(seed, ks.data(), ks.size());
    for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= ks[i];
}
