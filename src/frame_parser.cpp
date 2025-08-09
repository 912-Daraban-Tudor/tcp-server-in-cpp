#include "frame_parser.h"
#include <cstring>

FrameParser::FrameParser(size_t max_frame_size)
        : buffer_(), consume_offset_(0), max_frame_size_(max_frame_size), big_endian_(true), last_error_() {
    buffer_.reserve(4096);
}

static inline uint16_t read_uint16_be(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
static inline uint16_t read_uint16_le(const uint8_t* p) {
    return (uint16_t(p[1]) << 8) | uint16_t(p[0]);
}

std::vector<Frame> FrameParser::feed(const uint8_t* data, size_t len) {
    if (len == 0) return {};

    // append incoming data
    buffer_.insert(buffer_.end(), data, data + len);

    std::vector<Frame> ready;
    // parsing loop
    while (true) {
        size_t available = buffer_.size() - consume_offset_;
        if (available < 4) break; // not enough for header

        const uint8_t* ptr = buffer_.data() + consume_offset_;
        uint16_t message_size = big_endian_ ? read_uint16_be(ptr) : read_uint16_le(ptr);

        // validation: message_size must include header and be sensible
        if (message_size < 4) {
            last_error_ = "Invalid message_size < 4";
            throw std::runtime_error(last_error_);
        }
        if (message_size > max_frame_size_) {
            last_error_ = "Invalid message_size > max_frame_size";
            throw std::runtime_error(last_error_);
        }

        if (available < message_size) break; // need more bytes

        Frame f;
        f.message_size = message_size;
        f.message_type = ptr[2];
        f.message_sequence = ptr[3];

        size_t payload_len = message_size - 4;
        if (payload_len > 0) {
            f.payload.assign(ptr + 4, ptr + 4 + payload_len);
        }

        ready.push_back(std::move(f));
        consume_offset_ += message_size;

        // occasionally compact buffer to avoid unbounded memory growth
        if (consume_offset_ > 4096) {
            // erase consumed prefix
            buffer_.erase(buffer_.begin(), buffer_.begin() + consume_offset_);
            consume_offset_ = 0;
        }
    }

    // if we've consumed everything, reset buffer entirely
    if (consume_offset_ == buffer_.size()) {
        buffer_.clear();
        consume_offset_ = 0;
    }

    return ready;
}
