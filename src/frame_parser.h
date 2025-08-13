#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include "wire.h"

// wire header is 4 bytes (BE16 size, type, seq)
struct Frame {
    uint16_t             message_size;
    uint8_t              message_type;
    uint8_t              message_sequence;
    std::vector<uint8_t> payload;
};

class FrameParser {
public:
    explicit FrameParser(std::size_t max_frame_size = 64 * 1024);

    /** feed bytes, may return multiple frames
     * Throws runtime_error on malformed header or size
     */
    std::vector<Frame> feed(const uint8_t* data, std::size_t len);
    std::vector<Frame> feed(const std::vector<uint8_t>& data) {
        return feed(data.data(), data.size());
    }

private:
    std::vector<uint8_t> buffer_;
    std::size_t          read_pos_{0};
    std::size_t          max_frame_size_;
};
