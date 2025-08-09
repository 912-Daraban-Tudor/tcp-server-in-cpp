#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

struct Frame {
    uint16_t message_size; // includes header (4)
    uint8_t message_type;
    uint8_t message_sequence;
    std::vector<uint8_t> payload; // may be empty
};

class FrameParser {
public:
    // Construct parser with optional max frame size (default 64 KiB)
    explicit FrameParser(size_t max_frame_size = 64 * 1024);

    // Feed bytes into the parser; returns zero-or-more complete Frames.
    // Throws std::runtime_error on malformed frames (e.g., message_size < 4 or > max_frame_size).
    std::vector<Frame> feed(const uint8_t* data, size_t len);

    // Convenience overload
    std::vector<Frame> feed(const std::vector<uint8_t>& data) {
        return feed(data.data(), data.size());
    }

    // Get last error message (if you want non-exceptional behavior later)
    std::string last_error() const { return last_error_; }

    // Set whether message_size is parsed as big-endian (network order).
    // Default: true (big-endian). Set to false to parse little-endian.
    void set_big_endian(bool be) { big_endian_ = be; }

private:
    std::vector<uint8_t> buffer_;
    size_t consume_offset_;
    size_t max_frame_size_;
    bool big_endian_;
    std::string last_error_;
};
