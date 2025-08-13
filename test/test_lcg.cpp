#include "../src/crypto_lcg.h"
#include "../src/wire.h"

#include <cassert>
#include <iostream>
#include <random>
#include <string>
#include <vector>

// manual checksum for verification
static uint8_t manual_checksum8_str_ascii(std::string_view s) {
    unsigned v = 0;
    for (unsigned char ch : s) v += ch;
    return static_cast<uint8_t>(v & 0xFF);
}

int main() {
    // 1. checksum and seed  checks
    {
        std::string user = "user";
        std::string pass = "password";
        uint8_t us = checksum8_str_ascii(user);
        uint8_t ps = checksum8_str_ascii(pass);
        assert(us == manual_checksum8_str_ascii(user));
        assert(ps == manual_checksum8_str_ascii(pass));

        uint8_t seq = 87;
        uint32_t seed_lib = compute_seed(seq, us, ps);
        uint32_t seed_manual = (uint32_t(seq) << 16) | (uint32_t(us) << 8) | uint32_t(ps);
        assert(seed_lib == seed_manual);
    }

    // 2. xor twice with same seed returns original
    {
        std::string user = "ion";
        std::string pass = "bobbert";
        uint8_t seq = 7;

        uint8_t us = checksum8_str_ascii(user);
        uint8_t ps = checksum8_str_ascii(pass);
        uint32_t seed = compute_seed(seq, us, ps);

        std::vector<uint8_t> plain = {'h','e','l','l','o',' ','w','o','r','l','d'};
        std::vector<uint8_t> buf = plain;

        xor_with_lcg_inplace(seed, buf.data(), buf.size());   // encrypt
        xor_with_lcg_inplace(seed, buf.data(), buf.size());   // decrypt

        assert(buf == plain);
    }

    // 3. first keystream byte is next_key & 0xFF
    {
        std::string user = "u";
        std::string pass = "p";
        uint8_t seq = 2;
        uint8_t us = checksum8_str_ascii(user);
        uint8_t ps = checksum8_str_ascii(pass);
        uint32_t seed = compute_seed(seq, us, ps);

        uint8_t b0;
        {
            uint32_t s = seed;
            s = lcg_next(s);
            b0 = static_cast<uint8_t>(s & 0xFF);
        }
        uint8_t out[1] = {0};
        xor_with_lcg_inplace(seed, out, 1);
        assert(out[0] == b0);
    }

    // 4. same seed must result in same keystream
    {
        std::string user = "same";
        std::string pass = "seed";
        uint8_t seq = 99;
        uint32_t seed = compute_seed(seq, checksum8_str_ascii(user), checksum8_str_ascii(pass));

        std::vector<uint8_t> a(1024, 0);
        std::vector<uint8_t> b(1024, 0);

        xor_with_lcg_inplace(seed, a.data(), a.size());
        xor_with_lcg_inplace(seed, b.data(), b.size());

        assert(a == b);
    }

    // 5. different seq/user/pass -> different keystream
    {
        std::string user = "aaa";
        std::string pass = "bbb";
        uint8_t seq = 1;
        uint32_t seed1 = compute_seed(seq, checksum8_str_ascii(user), checksum8_str_ascii(pass));
        uint32_t seed2 = compute_seed(static_cast<uint8_t>(seq+1), checksum8_str_ascii(user), checksum8_str_ascii(pass));
        uint32_t seed3 = compute_seed(seq, checksum8_str_ascii("aac"), checksum8_str_ascii(pass));
        uint32_t seed4 = compute_seed(seq, checksum8_str_ascii(user), checksum8_str_ascii("bbc"));

        std::vector<uint8_t> k1(128, 0), k2(128, 0), k3(128, 0), k4(128, 0);
        xor_with_lcg_inplace(seed1, k1.data(), k1.size());
        xor_with_lcg_inplace(seed2, k2.data(), k2.size());
        xor_with_lcg_inplace(seed3, k3.data(), k3.size());
        xor_with_lcg_inplace(seed4, k4.data(), k4.size());

        assert(k1 != k2);
        assert(k1 != k3);
        assert(k1 != k4);
    }

    // 6. empty buffer
    {
        uint32_t seed = compute_seed(0, 0, 0);
        uint8_t* ptr = nullptr;
        xor_with_lcg_inplace(seed, ptr, 0);
        std::vector<uint8_t> v;
        xor_with_lcg(seed, v);
    }

    // 7. large buffer aprox 64 KiB
    {
        std::string user = "perf";
        std::string pass = "check";
        uint8_t seq = 200;
        uint32_t seed = compute_seed(seq, checksum8_str_ascii(user), checksum8_str_ascii(pass));

        std::vector<uint8_t> buf(64 * 1024, 0);
        xor_with_lcg(seed, buf);
        /** XOR again must return to zero */
        xor_with_lcg(seed, buf);
        for (auto b : buf) assert(b == 0);
    }

    std::cout << "LCG tests passed\n";
    return 0;
}
