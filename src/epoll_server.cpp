#include <vector>
#include <string>
#include <unordered_map>
#include <iostream>
#include <cstring>
#include <cerrno>

#include "wire.h"
#include "frame_parser.h"
#include "crypto_lcg.h"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

using socket_t = int;

namespace {
    constexpr int    MAX_EVENTS  = 1024;
    constexpr size_t IO_BUF_SIZE = 4096;

    void close_fd(socket_t s) noexcept {
        if (s >= 0)
            ::close(s);
    }

    void ignore_sigpipe() noexcept {
        ::signal(SIGPIPE, SIG_IGN);
    }

    bool set_nonblocking(int fd){
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0)
            return false;
        return ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    bool set_reuseaddr(int fd){
        int one = 1;
        return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0;
    }

    bool set_nodelay(int fd){
        int one = 1;
        return ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) == 0;
    }

    void epoll_add(int epfd, int fd, uint32_t events){
        epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (::epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) ::perror("epoll_ctl ADD");
    }

    void epoll_mod(int epfd, int fd, uint32_t events){
        epoll_event ev{};
        ev.events = events;
        ev.data.fd = fd;
        if (::epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0) ::perror("epoll_ctl MOD");
    }

    void epoll_del(int epfd, int fd){
        if (::epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr) < 0)
            ::perror("epoll_ctl DEL");
    }

    std::vector<uint8_t> make_status_payload(uint16_t code) {
        std::vector<uint8_t> status(2);
        put_be16(status.data(), code);
        return status;
    }

    struct Connection {
        int                  fd = -1;
        FrameParser          parser{};
        bool                 logged_in = false;
        uint8_t              user_sum = 0;
        uint8_t              pass_sum = 0;
        std::vector<uint8_t> write_buf;
        size_t               write_off = 0;
        bool                 want_write = false;
    };

    void handle_frame(Connection& c, const Frame& f) {
        switch (f.message_type) {
            case MSG_LOGIN_REQ: {
                if (f.payload.size() < USER_PASS_FIELD * 2) {
                    auto status = make_status_payload(0);
                    auto resp   = build_frame(MSG_LOGIN_RESP, f.message_sequence, status);
                    c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
                    c.want_write = true;
                    return;
                }

                const std::string user = parse_asciiz32(f.payload, 0);
                const std::string pass = parse_asciiz32(f.payload, USER_PASS_FIELD);

                c.user_sum  = checksum8_str_ascii(user);
                c.pass_sum  = checksum8_str_ascii(pass);
                c.logged_in = true;

                auto status = make_status_payload(1);
                auto resp = build_frame(MSG_LOGIN_RESP, f.message_sequence, status);
                c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
                c.want_write = true;
                return;
            }

            case MSG_ECHO_REQ: {
                if (!c.logged_in) return;
                if (f.payload.size() < 2) return;

                const uint16_t cipher_len = be16(f.payload.data());

                if (cipher_len > f.payload.size() - 2) return;

                std::vector<uint8_t> resp_payload(2 + cipher_len);
                put_be16(resp_payload.data(), cipher_len);

                if (cipher_len) {
                    std::memcpy(resp_payload.data() + 2, f.payload.data() + 2, cipher_len);
                    const uint32_t seed = compute_seed(f.message_sequence, c.user_sum, c.pass_sum);
                    xor_with_lcg_inplace(seed, resp_payload.data() + 2, cipher_len);
                }

                auto resp = build_frame(MSG_ECHO_RESP, f.message_sequence, resp_payload);
                c.write_buf.insert(c.write_buf.end(), resp.begin(), resp.end());
                c.want_write = true;
                return;
            }

            default: {
                auto echo = build_frame(f.message_type, f.message_sequence, f.payload);
                c.write_buf.insert(c.write_buf.end(), echo.begin(), echo.end());
                c.want_write = true;
                return;
            }
        }
    }
} // namespace

int main(int argc, char** argv) {
    uint16_t port = 5555;
    if (argc >= 2) {
        try {
            unsigned long p = std::stoul(argv[1]);
            if (p > 65535)
                throw std::out_of_range("port");
            port = static_cast<uint16_t>(p);
        } catch (...) {
            std::cerr << "Invalid port\n"; return 1;
        }
    }

    ignore_sigpipe();

    // 1) create, bind, listen
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        ::perror("socket");
        return 1;
    }

    if (!set_reuseaddr(listen_fd))
        ::perror("setsockopt(SO_REUSEADDR)");
    if (!set_nonblocking(listen_fd)) {
        ::perror("fcntl O_NONBLOCK");
        close_fd(listen_fd);
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::perror("bind");
        close_fd(listen_fd);
        return 2;
    }
    if (::listen(listen_fd, 128) < 0) {
        ::perror("listen");
        close_fd(listen_fd);
        return 3;
    }
    std::cout << "[epoll] listening on 0.0.0.0:" << port << "\n";

    // 2) epoll setup
    const int epfd = ::epoll_create1(0);
    if (epfd < 0) {
        ::perror("epoll_create1");
        close_fd(listen_fd);
        return 4;
    }

    epoll_add(epfd, listen_fd, EPOLLIN);

    std::unordered_map<int, Connection> conns;
    std::vector<uint8_t> io_buf(IO_BUF_SIZE);
    std::vector<epoll_event> events(MAX_EVENTS);

    // 3) event loop
    while (true) {
        const int n = ::epoll_wait(epfd, events.data(), MAX_EVENTS, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::perror("epoll_wait"); break;
        }

        for (int i = 0; i < n; ++i) {
            const epoll_event& e = events[i];

            if (e.data.fd == listen_fd) {
                // accept as many as available
                while (true) {
                    sockaddr_in cli{};
                    socklen_t clilen = sizeof(cli);
                    int cfd = ::accept4(listen_fd, reinterpret_cast<sockaddr*>(&cli), &clilen, SOCK_NONBLOCK);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        ::perror("accept4");
                        break;
                    }
                    (void)set_nodelay(cfd); // best effort

                    Connection c;
                    c.fd = cfd;
                    conns.emplace(cfd, std::move(c));

                    epoll_add(epfd, cfd, EPOLLIN | EPOLLRDHUP);
                }
                continue;
            }

            // client fd
            const int fd = e.data.fd;
            auto it = conns.find(fd);
            if (it == conns.end()) continue;
            Connection& c = it->second;

            bool close_now = false;

            // readable / remote closed
            if (e.events & (EPOLLIN | EPOLLRDHUP)) {
                while (true) {
                    const ssize_t k = ::recv(fd, io_buf.data(), io_buf.size(), 0);
                    if (k == 0) {
                        close_now = true;
                        break;
                    }
                    if (k < 0)  {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                            break;
                        ::perror("recv");
                        close_now = true;
                        break;
                    }

                    try {
                        const auto frames = c.parser.feed(io_buf.data(), static_cast<size_t>(k));
                        for (const auto& f : frames)
                            handle_frame(c, f);
                    } catch (const std::exception& ex) {
                        std::cerr << "[epoll] parser error: " << ex.what() << "\n";
                        close_now = true;
                        break;
                    }
                }
            }

            // writable
            if (!close_now && (e.events & EPOLLOUT)) {
                while (c.write_off < c.write_buf.size()) {
                    const uint8_t* p = c.write_buf.data() + c.write_off;
                    const size_t nbytes = c.write_buf.size() - c.write_off;
                    const ssize_t sent = ::send(fd, p, nbytes, 0);
                    if (sent > 0) {
                        c.write_off += static_cast<size_t>(sent);
                    } else if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        break;
                    } else if (sent < 0) {
                        ::perror("send");
                        close_now = true; break;
                    }
                }
                if (!close_now && c.write_off == c.write_buf.size()) {
                    c.write_buf.clear();
                    c.write_off = 0;
                    c.want_write = false;
                    epoll_mod(epfd, fd, EPOLLIN | EPOLLRDHUP);
                }
            }

            // enable EPOLLOUT if needed
            if (!close_now && c.want_write && !(e.events & EPOLLOUT)) {
                epoll_mod(epfd, fd, EPOLLIN | EPOLLOUT | EPOLLRDHUP);
            }

            if (e.events & (EPOLLHUP | EPOLLERR)) close_now = true;

            if (close_now) {
                epoll_del(epfd, fd);
                close_fd(fd);
                conns.erase(it);
            }
        }
    }

    for (auto& [fd, _] : conns)
        close_fd(fd);
    close_fd(listen_fd);
    close_fd(epfd);
    return 0;
}
