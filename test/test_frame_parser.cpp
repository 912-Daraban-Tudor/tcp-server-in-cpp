#include "../src/frame_parser.h"

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

static void print_frame(const Frame &f) {
    std::cout << "frame size=" << f.message_size
              << " type=" << int(f.message_type)
              << " seq="  << int(f.message_sequence)
              << " payload_length=" << f.payload.size() << "\n";
}

int main() {
    static_assert(PROTO_HEADER_SIZE == 4, "header must be 4 bytes");

    FrameParser p;

    // 1. header split across two feeds
    {
        const std::vector<uint8_t> payload{'H','e','l','l','o'};
        auto frame1 = build_frame(1, 5, std::span<const uint8_t>(payload.data(), payload.size()));
        std::vector<uint8_t> part1(frame1.begin(), frame1.begin() + 2);
        std::vector<uint8_t> part2(frame1.begin() + 2, frame1.end());

        auto r1 = p.feed(part1);
        assert(r1.empty());

        auto r2 = p.feed(part2);
        assert(r2.size() == 1);
        print_frame(r2[0]);
        assert(r2[0].message_type == 1);
        assert(r2[0].message_sequence == 5);
        assert(r2[0].payload.size() == payload.size());
        assert(std::string(r2[0].payload.begin(), r2[0].payload.end()) == "Hello");
    }

    // 2. two frames concatenated in one read
    {
        const std::vector<uint8_t> p2{0x01,0x02};
        const std::vector<uint8_t> p3{};
        auto f2 = build_frame(2, 7, std::span<const uint8_t>(p2.data(), p2.size()));
        auto f3 = build_frame(3, 9, std::span<const uint8_t>(p3.data(), p3.size()));

        std::vector<uint8_t> cat;
        cat.reserve(f2.size() + f3.size());
        cat.insert(cat.end(), f2.begin(), f2.end());
        cat.insert(cat.end(), f3.begin(), f3.end());

        auto r = p.feed(cat);
        assert(r.size() == 2);
        print_frame(r[0]); print_frame(r[1]);
        assert(r[0].message_type == 2 && r[0].message_sequence == 7);
        assert(r[1].message_type == 3 && r[1].message_sequence == 9);
        assert(r[1].payload.empty());
    }

    // 3. payload split int diff bytes
    {
        const std::vector<uint8_t> pl{'a','b','c','d','e','f','g','h','i','j'};
        auto f = build_frame(0xFF, 0xAA, std::span<const uint8_t>(pl.data(), pl.size()));
        for (size_t i = 0; i < f.size(); ++i) {
            std::vector<uint8_t> chunk{f[i]};
            auto r = p.feed(chunk);
            if (i + 1 < f.size()) {
                assert(r.empty());
            } else {
                assert(r.size() == 1);
                print_frame(r[0]);
                assert(r[0].message_type == 0xFF);
                assert(r[0].message_sequence == 0xAA);
                assert(r[0].payload.size() == pl.size());
            }
        }
    }

    // 4. malformed length -> throws runtime error
    try {
        // size = 2 (invalid)
        std::vector<uint8_t> bad = {0x00, 0x02, 0x11, 0x22};
        (void)p.feed(bad);
        std::cerr << "expected exception for invalid size, but none thrown\n";
        return 2;
    } catch (const std::runtime_error &) {
    }

    // 5. oversize rejected, uses small max frame size
    try {
        FrameParser small(128);
        std::vector<uint8_t> big_payload(200, 0xAA); // 4+200 = 204 > 128
        auto big = build_frame(1, 1, std::span<const uint8_t>(big_payload.data(), big_payload.size()));
        (void)small.feed(big);
        std::cerr << "expected exception for oversize frame, but none thrown\n";
        return 3;
    } catch (const std::runtime_error &) {
    }

    // 6. big bound near FFFF works
    {
        const size_t payload_len = 65535u - PROTO_HEADER_SIZE; // 65531
        std::vector<uint8_t> big(payload_len, 0x5A);
        auto f = build_frame(2, 0x7E, std::span<const uint8_t>(big.data(), big.size()));
        FrameParser px; // default 64KiB, so 65535 fits
        auto r = px.feed(f);
        assert(r.size() == 1);
        assert(r[0].message_size == 65535);
        assert(r[0].payload.size() == payload_len);
        assert(r[0].message_type == 2);
        assert(r[0].message_sequence == 0x7E);
    }

    // 7. large payload in two chunks -> no early frame
    {
        FrameParser q;
        std::vector<uint8_t> big(4096, 0x77);
        auto f = build_frame(4, 4, std::span<const uint8_t>(big.data(), big.size()));


        std::vector<uint8_t> half(f.begin(), f.begin() + PROTO_HEADER_SIZE + 2048);
        auto r1 = q.feed(half);
        assert(r1.empty());


        std::vector<uint8_t> rest(f.begin() + half.size(), f.end());
        auto r2 = q.feed(rest);
        assert(r2.size() == 1);
        assert(r2[0].payload.size() == big.size());
    }

    std::cout << "all FrameParser tests passed!\n";
    return 0;
}
