#include "frame_parser.h"
#include <algorithm>
#include <stdexcept>

namespace {
    constexpr std::size_t COMPACT_ABS_THRESHOLD = 8 * 1024;
}

FrameParser::FrameParser(std::size_t max_frame_size)
        : buffer_(), read_pos_(0), max_frame_size_(max_frame_size) {
    buffer_.reserve(4096);
}

std::vector<Frame> FrameParser::feed(const uint8_t* data, std::size_t len) {
    if (len == 0) return {};
    buffer_.insert(buffer_.end(), data, data + len);

    std::vector<Frame> ready;
    while (true) {
        const std::size_t available = buffer_.size() - read_pos_;
        if (available < PROTO_HEADER_SIZE) break;

        const uint8_t* ptr = buffer_.data() + read_pos_;
        const uint16_t message_size = be16(ptr);

        if (message_size < PROTO_HEADER_SIZE) {
            throw std::runtime_error("invalid message_size < header");
        }
        if (message_size > max_frame_size_) {
            throw std::runtime_error("invalid message_size > max_frame_size");
        }
        if (available < message_size) break;

        Frame f;
        f.message_size     = message_size;
        f.message_type     = ptr[2];
        f.message_sequence = ptr[3];

        const std::size_t payload_len = message_size - PROTO_HEADER_SIZE;
        f.payload.assign(ptr + PROTO_HEADER_SIZE, ptr + PROTO_HEADER_SIZE + payload_len);

        ready.push_back(std::move(f));
        read_pos_ += message_size;

        if (read_pos_ >= COMPACT_ABS_THRESHOLD || read_pos_ >= buffer_.size() / 2) {
            auto it = buffer_.begin() + static_cast<std::ptrdiff_t>(read_pos_);
            buffer_.erase(buffer_.begin(), it);
            read_pos_ = 0;
        }
    }

    if (read_pos_ == buffer_.size()) {
        buffer_.clear();
        read_pos_ = 0;
    }
    return ready;
}
