// server_epoll.cpp — Linux-only, epoll (level-triggered), single-threaded
// Protocol and behavior are identical to server.cpp; only the I/O model changes.

#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <iostream>
#include <sstream>
#include <cstring>
#include <cerrno>

#include "frame_parser.h"
#include "protocol.h"
#include "crypto_lcg.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

using socket_t = int;

constexpr int    MAX_EVENTS   = 1024;
constexpr size_t IO_BUF_SIZE  = 4096;

static void closesock(socket_t s){ if (s >= 0) ::close(s); }
static void ignore_sigpipe()    { signal(SIGPIPE, SIG_IGN); }

static int set_nonblocking(int fd){
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_reuseaddr(int fd){
    int one = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
}

static int set_nodelay(int fd){
    int one = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

// build a framed message with BE16 size header
static std::vector<uint8_t> build_frame_be(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload) {
    const size_t total = PROTO_HEADER_SIZE + payload.size();
    if (total > 0xFFFF) throw std::runtime_error("frame too large");
    const uint16_t size = static_cast<uint16_t>(total);

    std::vector<uint8_t> out;
    out.reserve(total);
    out.push_back(uint8_t((size >> 8) & 0xFF));
    out.push_back(uint8_t(size & 0xFF));
    out.push_back(type);
    out.push_back(seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

static inline uint32_t compute_seed(uint8_t seq, uint8_t user_sum, uint8_t pass_sum) {
    return (uint32_t(seq) << 16) | (uint32_t(user_sum) << 8) | uint32_t(pass_sum);
}

struct Connection {
    int                 fd = -1;
    FrameParser         parser;
    bool                logged_in = false;
    uint8_t             user_sum = 0;
    uint8_t             pass_sum = 0;
    std::vector<uint8_t> write_buf;   // pending bytes to send
};

static void epoll_add(int epfd, int fd, uint32_t events, void* ptr){
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = ptr;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) perror("epoll_ctl ADD");
}

static void epoll_mod(int epfd, int fd, uint32_t events, void* ptr){
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = ptr;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0) perror("epoll_ctl MOD");
}

static void epoll_del(int epfd, int fd){
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr) < 0) perror("epoll_ctl DEL");
}

// handle one complete application frame; may append bytes to conn.write_buf
static void handle_frame(Connection& c, const Frame& f) {
    switch (f.message_type) {
        case MSG_LOGIN_REQ: {
            if (f.payload.size() < USER_PASS_FIELD * 2) {
                uint16_t code_be = htons(0); // FAILED
                std::vector<uint8_t> status(2);
                std::memcpy(status.data(), &code_be, 2);
                auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
                c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
                // Close will be handled by main loop after send finishes or on error
                return;
            }

            const std::string user = parse_asciiz32(f.payload, 0);
            const std::string pass = parse_asciiz32(f.payload, USER_PASS_FIELD);

            c.user_sum  = checksum8_str_ascii(user);
            c.pass_sum  = checksum8_str_ascii(pass);
            c.logged_in = true; // spec: any creds are valid

            uint16_t code_be = htons(1); // OK
            std::vector<uint8_t> status(2);
            std::memcpy(status.data(), &code_be, 2);
            auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
            c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
            return;
        }

        case MSG_ECHO_REQ: {
            if (!c.logged_in) {
                // silently ignore per our previous behavior
                return;
            }
            if (f.payload.size() < 2) {
                return;
            }

            const uint16_t cipher_len = be16(f.payload.data());
            if (cipher_len > f.payload.size() - 2) {
                // length mismatch; ignore
                return;
            }

            // Build response payload: BE16(len) + copy of cipher, then decrypt in place
            std::vector<uint8_t> resp_payload(2 + cipher_len);
            put_be16(resp_payload.data(), cipher_len);
            if (cipher_len) {
                std::memcpy(resp_payload.data() + 2, f.payload.data() + 2, cipher_len);
                const uint32_t seed = compute_seed(f.message_sequence, c.user_sum, c.pass_sum);
                xor_with_lcg_inplace(seed, resp_payload.data() + 2, cipher_len);
            }

            auto resp = build_frame_be(MSG_ECHO_RESP, f.message_sequence, resp_payload);
            c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
            return;
        }

        default: {
            // Unknown type: echo back safely
            auto echo = build_frame_be(f.message_type, f.message_sequence, f.payload);
            c.write_buf.insert(c.write_buf.end(), echo.begin(), echo.end());
            return;
        }
    }
}

int main(int argc, char** argv) {
    uint16_t port = 5555;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    ignore_sigpipe();

    // 1) create, bind, listen (non-blocking)
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    set_reuseaddr(listen_fd);
    set_nonblocking(listen_fd);
    set_nodelay(listen_fd);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind"); closesock(listen_fd); return 2;
    }
    if (::listen(listen_fd, 128) < 0) {
        perror("listen"); closesock(listen_fd); return 3;
    }
    std::cout << "[epoll] listening on 0.0.0.0:" << port << "\n";

    // 2) epoll setup
    const int epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); closesock(listen_fd); return 4; }

    // Use the listening fd itself as the data pointer for identification
    epoll_event ev{};
    ev.events  = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) { perror("epoll_ctl ADD listen"); return 5; }

    std::unordered_map<int, Connection> conns;
    std::vector<uint8_t> io_buf(IO_BUF_SIZE);

    // 3) event loop
    std::vector<epoll_event> events(MAX_EVENTS);

    for (;;) {
        const int n = epoll_wait(epfd, events.data(), MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("epoll_wait"); break;
        }

        for (int i = 0; i < n; ++i) {
            const epoll_event& e = events[i];

            // 3a) listener: accept as many as available
            if (e.data.fd == listen_fd) {
                for (;;) {
                    sockaddr_in cli{};
                    socklen_t   clilen = sizeof(cli);
                    int cfd = ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&cli), &clilen, SOCK_NONBLOCK);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        perror("accept4"); break;
                    }
                    set_nodelay(cfd);

                    // add to epoll with read interest only (we enable write when we have data to send)
                    Connection c;
                    c.fd = cfd;
                    conns.emplace(cfd, std::move(c));

                    epoll_event cev{};
                    cev.events  = EPOLLIN | EPOLLRDHUP;
                    cev.data.fd = cfd; // we’ll look up in the map by fd
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) perror("epoll_ctl ADD client");
                }
                continue;
            }

            // 3b) look up the connection by fd
            const int fd = e.data.fd;
            auto it = conns.find(fd);
            if (it == conns.end()) {
                // should not happen
                continue;
            }
            Connection& c = it->second;

            bool close_now = false;

            // 3c) readable or remote closed
            if (e.events & (EPOLLIN | EPOLLRDHUP)) {
                for (;;) {
                    const ssize_t k = ::recv(fd, io_buf.data(), io_buf.size(), 0);
                    if (k == 0) { close_now = true; break; }                // peer closed
                    if (k < 0)  {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break; // no more data
                        perror("recv"); close_now = true; break;
                    }

                    try {
                        const auto frames = c.parser.feed(io_buf.data(), static_cast<size_t>(k));
                        for (const auto& f : frames) {
                            handle_frame(c, f);
                        }
                    } catch (const std::exception& ex) {
                        std::cerr << "[epoll] parser error: " << ex.what() << "\n";
                        close_now = true;
                        break;
                    }
                }
            }

            // 3d) writable: flush write buffer
            if (!close_now && (e.events & EPOLLOUT)) {
                while (!c.write_buf.empty()) {
                    const ssize_t sent = ::send(fd, c.write_buf.data(), c.write_buf.size(),
#ifdef MSG_NOSIGNAL
                                                MSG_NOSIGNAL
#else
                            0
#endif
                    );
                    if (sent > 0) {
                        c.write_buf.erase(c.write_buf.begin(), c.write_buf.begin() + sent);
                    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break; // try later
                    } else if (sent < 0) {
                        perror("send");
                        close_now = true;
                        break;
                    }
                }

                // if fully flushed, stop watching for write
                if (!close_now && c.write_buf.empty()) {
                    epoll_event cev{};
                    cev.events  = EPOLLIN | EPOLLRDHUP;
                    cev.data.fd = fd;
                    epoll_mod(epfd, fd, cev.events, cev.data.ptr);
                }
            }

            // 3e) if we have data to send and we’re not already watching for write, enable EPOLLOUT
            if (!close_now && !c.write_buf.empty() && !(e.events & EPOLLOUT)) {
                epoll_event cev{};
                cev.events  = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
                cev.data.fd = fd;
                epoll_mod(epfd, fd, cev.events, cev.data.ptr);
            }

            // 3f) handle errors/hangups
            if (e.events & (EPOLLHUP | EPOLLERR)) {
                close_now = true;
            }

            if (close_now) {
                epoll_del(epfd, fd);
                closesock(fd);
                conns.erase(it);
            }
        }
    }

    for (auto& [fd, _] : conns) closesock(fd);
    closesock(listen_fd);
    closesock(epfd);
    return 0;
}
