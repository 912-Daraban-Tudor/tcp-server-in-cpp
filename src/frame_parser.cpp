#include "frame_parser.h"
#include <cstring>

// When to compact the internal buffer: either consumed >= 8 KiB OR >= 50% of buffer
constexpr std::size_t COMPACT_ABS_THRESHOLD   = 8 * 1024;
constexpr std::size_t COMPACT_RATIO_DENOM     = 2;

static inline uint16_t read_uint16_be(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
static inline uint16_t read_uint16_le(const uint8_t* p) {
    return (uint16_t(p[1]) << 8) | uint16_t(p[0]);
}

FrameParser::FrameParser(std::size_t max_frame_size)
        : buffer_(),
          consume_offset_(0),
          max_frame_size_(max_frame_size),
          big_endian_(true),
          last_error_() {
    buffer_.reserve(4096);
}

std::vector<Frame> FrameParser::feed(const uint8_t* data, std::size_t len) {
    if (len == 0) return {};

    // Append incoming data
    buffer_.insert(buffer_.end(), data, data + len);

    std::vector<Frame> ready;

    // Parsing loop - extract as many complete frames as present
    for (;;) {
        const std::size_t available = buffer_.size() - consume_offset_;
        if (available < FRAME_HEADER_SIZE) break; // Not enough for header

        const uint8_t* ptr = buffer_.data() + consume_offset_;
        const uint16_t message_size = big_endian_ ? read_uint16_be(ptr) : read_uint16_le(ptr);

        // Validate header size field
        if (message_size < FRAME_HEADER_SIZE) {
            last_error_ = "Invalid message_size < header (4)";
            throw std::runtime_error(last_error_);
        }
        if (message_size > max_frame_size_) {
            last_error_ = "Invalid message_size > max_frame_size";
            throw std::runtime_error(last_error_);
        }

        if (available < message_size) break; // Need more bytes

        // We have a full frame
        Frame f;
        f.message_size     = message_size;
        f.message_type     = ptr[2];
        f.message_sequence = ptr[3];

        const std::size_t payload_len = message_size - FRAME_HEADER_SIZE;
        if (payload_len > 0) {
            f.payload.assign(ptr + FRAME_HEADER_SIZE, ptr + FRAME_HEADER_SIZE + payload_len);
        }

        ready.push_back(std::move(f));
        consume_offset_ += message_size;

        // Occasionally compact buffer to avoid unbounded growth / large prefixes
        if (consume_offset_ >= COMPACT_ABS_THRESHOLD ||
            consume_offset_ >= buffer_.size() / COMPACT_RATIO_DENOM) {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(consume_offset_));
            consume_offset_ = 0;
        }
    }

    // If we've consumed everything, reset buffer entirely
    if (consume_offset_ == buffer_.size()) {
        buffer_.clear();
        consume_offset_ = 0;
    }

    return ready;
}
