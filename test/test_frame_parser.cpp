// test/test_frame_parser.cpp
#include "../src/frame_parser.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <string>

// Helper: build a frame byte vector for given type, seq, payload
static std::vector<uint8_t> build_frame(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload) {
    uint16_t size = 4 + static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> out;
    out.reserve(size);
    // big-endian message_size
    out.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(size & 0xFF));
    out.push_back(type);
    out.push_back(seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

static void print_frame(const Frame &f) {
    std::cout << "Frame size=" << f.message_size
              << " type=" << int(f.message_type)
              << " seq="  << int(f.message_sequence)
              << " payload_len=" << f.payload.size() << "\n";
}

int main() {
    FrameParser p;

    // Test 1: header split across two feeds
    auto frame1 = build_frame(1, 5, std::vector<uint8_t>{'H','e','l','l','o'});
    std::vector<uint8_t> part1(frame1.begin(), frame1.begin() + 2); // size hi/lo only
    std::vector<uint8_t> part2(frame1.begin() + 2, frame1.end());

    auto res1 = p.feed(part1);
    assert(res1.empty()); // not complete yet
    auto res2 = p.feed(part2);
    assert(res2.size() == 1);
    print_frame(res2[0]);
    assert(res2[0].payload.size() == 5);
    assert(std::string(res2[0].payload.begin(), res2[0].payload.end()) == "Hello");

    // Test 2: two frames concatenated in one feed
    auto frame2 = build_frame(2, 7, std::vector<uint8_t>{0x01,0x02});
    auto frame3 = build_frame(3, 9, std::vector<uint8_t>{});
    std::vector<uint8_t> cat;
    cat.insert(cat.end(), frame2.begin(), frame2.end());
    cat.insert(cat.end(), frame3.begin(), frame3.end());

    auto res3 = p.feed(cat);
    assert(res3.size() == 2);
    print_frame(res3[0]);
    print_frame(res3[1]);
    assert(res3[0].message_type == 2 && res3[1].message_type == 3);

    // Test 3: payload split across many small chunks (byte-by-byte)
    auto frame4 = build_frame(0xFF, 0xAA, std::vector<uint8_t>{'a','b','c','d','e','f','g','h','i','j'});
    for (size_t i = 0; i < frame4.size(); ++i) {
        std::vector<uint8_t> chunk{frame4[i]};
        auto r = p.feed(chunk);
        if (i < frame4.size() - 1) {
            assert(r.empty());
        } else {
            assert(r.size() == 1);
            print_frame(r[0]);
            assert(r[0].payload.size() == 10);
        }
    }

    // Test 4: malformed size (< 4) -> throws
    try {
        std::vector<uint8_t> bad = {0x00, 0x02, 0x11, 0x22}; // size=2
        p.feed(bad);
        std::cerr << "Expected exception for invalid size, but none thrown\n";
        return 2;
    } catch (const std::runtime_error &) {
        // ok
    }

    // Test 5: oversize frame rejected (use a tiny max_frame_size)
    try {
        FrameParser tiny(128);
        auto big_payload = std::vector<uint8_t>(200, 0xAA); // 4+200 = 204 > 128
        auto big = build_frame(1, 1, big_payload);
        (void)tiny.feed(big);
        std::cerr << "Expected exception for oversize frame, but none thrown\n";
        return 3;
    } catch (const std::runtime_error &) {
        // ok
    }

    // Test 6: boundary near 0xFFFF works (default max 64 KiB; 65535 fits)
    {
        const size_t payload_len = 65535u - 4u; // = 65531
        std::vector<uint8_t> big(payload_len, 0x5A);
        auto f = build_frame(2, 0x7E, big);
        FrameParser px; // default 64*1024 = 65536; 65535 <= 65536 OK
        auto r = px.feed(f);
        assert(r.size() == 1);
        assert(r[0].message_size == 65535);
        assert(r[0].payload.size() == payload_len);
        assert(r[0].message_type == 2);
        assert(r[0].message_sequence == 0x7E);
    }

    std::cout << "All FrameParser tests passed.\n";
    return 0;
}
