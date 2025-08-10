// server.cpp — Linux-only, spec-aligned, polished
// Header: BE16 size (incl header), type, seq
// Types: LoginReq=0, LoginResp=1, EchoReq=2, EchoResp=3

#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <thread>
#include <mutex>
#include <sstream>
#include <cstring>
#include <atomic>
#include <cerrno>

#include "frame_parser.h"
#include "protocol.h"
#include "crypto_lcg.h"

// ---- POSIX networking (Linux-only) ----
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

using socket_t = int;

// --- global run control for graceful shutdown ---
static std::atomic<bool> g_running{true};
static int g_listen_fd = -1;
static void on_signal(int) {
    g_running = false;
    if (g_listen_fd >= 0) ::close(g_listen_fd); // wake accept()
}

// --- small platform helpers ---
static void net_init() { signal(SIGPIPE, SIG_IGN); }
static void net_cleanup() {}
static void closesock(socket_t s) { if (s >= 0) ::close(s); }
static int  set_reuseaddr(socket_t s) { int opt = 1; return ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); }

// --- logging ---
static std::mutex g_log;
static void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log);
    std::cout << s << '\n';
}

// tiny hex sampler for debug
static std::string hex_sample(const std::vector<uint8_t>& v, size_t max=32) {
    static const char* hexd="0123456789ABCDEF";
    std::string s; s.reserve(max*3);
    for (size_t i=0;i<v.size() && i<max;i++){
        uint8_t b = v[i];
        s.push_back(hexd[b>>4]); s.push_back(hexd[b&0xF]); s.push_back(' ');
    }
    if (v.size()>max) s += "...";
    return s;
}

// --- robust send (handles partial writes, no SIGPIPE) ---
static bool send_all(socket_t s, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t k = ::send(s, p, n,
#ifdef MSG_NOSIGNAL
                           MSG_NOSIGNAL
#else
                0
#endif
        );
        if (k <= 0) return false;
        p += static_cast<size_t>(k);
        n -= static_cast<size_t>(k);
    }
    return true;
}

// --- frame builder (BE header) ---
static std::vector<uint8_t> build_frame_be(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload) {
    size_t total = 4 + payload.size();
    if (total > 0xFFFF) throw std::runtime_error("frame too large");
    uint16_t size = static_cast<uint16_t>(total);

    std::vector<uint8_t> out;
    out.reserve(total);
    out.push_back(uint8_t((size >> 8) & 0xFF));
    out.push_back(uint8_t(size & 0xFF));
    out.push_back(type);
    out.push_back(seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

struct ConnectionContext {
    bool    logged_in = false;
    uint8_t user_sum  = 0;
    uint8_t pass_sum  = 0;
};

static void handle_connection(socket_t client) {
    {
        std::ostringstream os;
        os << "[conn] started on thread " << std::hash<std::thread::id>{}(std::this_thread::get_id());
        log_line(os.str());
    }

    // 15s receive/send timeout to avoid wedged sockets
    timeval tv{15, 0};
    ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    // Lower latency + keepalive
    int one = 1;
    ::setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    ::setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));

    FrameParser parser; // big-endian size framing
    std::vector<uint8_t> rx(4096);
    ConnectionContext ctx;

    for (;;) {
        int n = ::recv(client, rx.data(), static_cast<int>(rx.size()), 0);
        if (n == 0) { log_line("[conn] peer closed"); break; }
        if (n < 0)  { log_line("[conn] recv error; closing"); break; }

        try {
            auto frames = parser.feed(rx.data(), static_cast<size_t>(n));
            for (auto& f : frames) {
                {
                    std::ostringstream os;
                    os << "[frame] size=" << f.message_size
                       << " type=" << int(f.message_type)
                       << " seq="  << int(f.message_sequence)
                       << " payload_len=" << f.payload.size();
                    log_line(os.str());
                }

                switch (f.message_type) {
                    case MSG_LOGIN_REQ: { // 0
                        if (f.payload.size() < USER_PASS_FIELD * 2) {
                            uint16_t code_be = htons(0); // FAILED
                            std::vector<uint8_t> status(2);
                            std::memcpy(status.data(), &code_be, 2);
                            auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
                            (void)send_all(client, resp.data(), resp.size());
                            log_line("[conn] closed (bad login payload)");
                            closesock(client);
                            return;
                        }

                        std::string user = parse_asciiz32(f.payload, 0);
                        std::string pass = parse_asciiz32(f.payload, USER_PASS_FIELD);

                        // Spec: any username/password are valid
                        bool ok = true;

                        ctx.user_sum  = checksum8_bytes(reinterpret_cast<const uint8_t*>(user.data()), user.size());
                        ctx.pass_sum  = checksum8_bytes(reinterpret_cast<const uint8_t*>(pass.data()), pass.size());
                        ctx.logged_in = ok;

                        {
                            std::ostringstream os;
                            os << "  login user=\"" << user << "\" user_sum=0x"
                               << std::hex << int(ctx.user_sum) << " pass_sum=0x" << int(ctx.pass_sum) << std::dec;
                            log_line(os.str());
                        }

                        uint16_t code_be = htons(ok ? 1 : 0);
                        std::vector<uint8_t> status(2);
                        std::memcpy(status.data(), &code_be, 2);
                        auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
                        if (!send_all(client, resp.data(), resp.size())) { log_line("[conn] send error; closing"); closesock(client); return; }

                        if (!ok) {
                            log_line("[conn] closed (login failed)");
                            closesock(client);
                            return;
                        }
                        break;
                    }

                    case MSG_ECHO_REQ: { // 2
                        if (!ctx.logged_in) { log_line("  echo before login; ignoring"); break; }
                        if (f.payload.size() < 2) { log_line("  echo payload too short"); break; }

                        uint16_t cipher_len = be16(f.payload.data());
                        if (cipher_len > f.payload.size() - 2) {
                            std::ostringstream os; os << "  echo length mismatch: " << cipher_len
                                                      << " > " << (f.payload.size() - 2);
                            log_line(os.str());
                            break;
                        }

                        std::vector<uint8_t> msg(f.payload.begin() + 2, f.payload.begin() + 2 + cipher_len);

                        uint32_t seed = (uint32_t(f.message_sequence) << 16) |
                                        (uint32_t(ctx.user_sum) << 8) |
                                        uint32_t(ctx.pass_sum);
                        xor_with_lcg(seed, msg); // decrypt → plaintext

                        bool printable = !msg.empty();
                        for (auto b : msg) if (b < 32 || b > 126) { printable = false; break; }
                        if (printable) {
                            std::string s(msg.begin(), msg.end());
                            log_line(std::string("  decrypted ascii: \"") + s + "\"");
                        } else {
                            std::ostringstream os; os << "  decrypted len=" << msg.size();
                            log_line(os.str());
                        }

                        // Echo Response (type=3): BE16(len) + plaintext, same seq
                        std::vector<uint8_t> resp_payload(2 + msg.size());
                        put_be16(resp_payload.data(), static_cast<uint16_t>(msg.size()));
                        std::copy(msg.begin(), msg.end(), resp_payload.begin() + 2);

                        auto resp = build_frame_be(MSG_ECHO_RESP, f.message_sequence, resp_payload);
                        if (!send_all(client, resp.data(), resp.size())) { log_line("[conn] send error; closing"); closesock(client); return; }
                        break;
                    }

                    default: {
                        std::ostringstream os; os << "  unknown type="<<int(f.message_type)
                                                  << " payload: " << hex_sample(f.payload);
                        log_line(os.str());
                        // Safe echo back same type/seq/payload
                        auto echo = build_frame_be(f.message_type, f.message_sequence, f.payload);
                        if (!send_all(client, echo.data(), echo.size())) { log_line("[conn] send error; closing"); closesock(client); return; }
                        break;
                    }
                } // switch
            } // frames
        } catch (const std::exception& e) {
            std::ostringstream os; os << "[conn] parser error: " << e.what() << " — closing";
            log_line(os.str());
            break;
        }
    } // recv loop

    closesock(client);
    log_line("[conn] closed");
}

int main(int argc, char** argv) {
    uint16_t port = 5555;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    // signals: ignore SIGPIPE (already in net_init), handle INT/TERM for graceful exit
    net_init();
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);

    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { std::cerr << "socket() failed\n"; net_cleanup(); return 1; }
    g_listen_fd = s;
    set_reuseaddr(s);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind() failed\n"; closesock(s); net_cleanup(); return 2;
    }
    if (::listen(s, 128) < 0) {
        std::cerr << "listen() failed\n"; closesock(s); net_cleanup(); return 3;
    }

    std::cout << "[server] listening on 0.0.0.0:" << port << "\n";

    // Accept loop — spawn a detached thread per connection (simple concurrency)
    for (;;) {
        sockaddr_in cli{}; socklen_t clilen = sizeof(cli);
        socket_t c = ::accept(s, reinterpret_cast<sockaddr*>(&cli), &clilen);
        if (!g_running) break;
        if (c < 0) {
            if (!g_running && (errno == EBADF || errno == EINTR)) break;
            std::cerr << "accept() error, continuing\n";
            continue;
        }

        char ip[INET_ADDRSTRLEN] = {0};
        ::inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        uint16_t cport = ntohs(cli.sin_port);
        {
            std::ostringstream os; os << "[accept] " << ip << ":" << cport;
            log_line(os.str());
        }

        std::thread(handle_connection, c).detach();
    }

    closesock(s);
    net_cleanup();
    return 0;
}
