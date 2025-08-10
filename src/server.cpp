// server - spec aligned
// - Header: [0..1]=BE16 size (incl. header), [2]=type, [3]=seq
// - Types:  LoginReq=0, LoginResp=1, EchoReq=2, EchoResp=3
// - LoginReq payload:  username[32] (ASCIIZ), password[32] (ASCIIZ)
// - LoginResp payload: BE16 status (0x0001 OK, 0x0000 FAILED). On FAILED: disconnect client.
// - EchoReq  payload:  BE16 cipher_len + cipher bytes
// - EchoResp payload:  BE16 plain_len  + plain bytes (same seq as request)

#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <thread>
#include <atomic>
#include <iomanip>
#include <sstream>

#include "frame_parser.h"
#include "protocol.h"
#include "crypto_lcg.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
static void net_init() { WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa); }
static void net_cleanup() { WSACleanup(); }
static void closesock(socket_t s) { closesocket(s); }
static int set_reuseaddr(socket_t s) {
    BOOL opt = TRUE; return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
}
#else
#include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <signal.h>
  using socket_t = int;
  static void net_init() { signal(SIGPIPE, SIG_IGN); }
  static void net_cleanup() {}
  static void closesock(socket_t s) { close(s); }
  static int set_reuseaddr(socket_t s) {
      int opt = 1; return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  }
#endif

// ----- small helpers -----
static void hex_dump_locked(const std::vector<uint8_t>& v) {
    for (size_t i = 0; i < v.size(); ++i) {
        if (i && (i % 16 == 0)) std::cout << "\n";
        std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << int(v[i]) << " ";
    }
    std::cout << std::dec << "\n";
}

static std::vector<uint8_t> build_frame_be(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload) {
    uint16_t size = uint16_t(4 + payload.size());
    std::vector<uint8_t> out;
    out.reserve(size);
    out.push_back(uint8_t((size >> 8) & 0xFF));
    out.push_back(uint8_t(size & 0xFF));
    out.push_back(type);
    out.push_back(seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

struct ConnectionContext {
    bool   logged_in = false;
    uint8_t user_sum = 0;
    uint8_t pass_sum = 0;
};

// Optional: make logs per-line atomic (avoid interleaving)
#include <mutex>
static std::mutex g_log;
static void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log);
    std::cout << s << '\n';
}

// ----- per-connection handler -----
static void handle_connection(socket_t client) {
    {
        std::ostringstream os;
        os << "[conn] started on thread " << std::hash<std::thread::id>{}(std::this_thread::get_id());
        log_line(os.str());
    }

    FrameParser parser; // big-endian size
    std::vector<uint8_t> rx(4096);
    ConnectionContext ctx;

    // (Nice to have) receive timeout to avoid wedged connections
#ifdef _WIN32
    {
        DWORD tv_ms = 15000; // 15s
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv_ms), sizeof(tv_ms));
    }
#else
    {
        timeval tv{15, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
#endif

    for (;;) {
#ifdef _WIN32
        int n = recv(client, reinterpret_cast<char*>(rx.data()), (int)rx.size(), 0);
#else
        int n = recv(client, rx.data(), (int)rx.size(), 0);
#endif
        if (n == 0) { log_line("[conn] peer closed"); break; }
        if (n < 0)  { log_line("[conn] recv error; closing"); break; }

        try {
            auto frames = parser.feed(rx.data(), (size_t)n);
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
                            std::vector<uint8_t> status(2, 0x00); // 0x0000 FAILED
                            auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
#ifdef _WIN32
                            send(client, reinterpret_cast<const char*>(resp.data()), (int)resp.size(), 0);
#else
                            send(client, resp.data(), (int)resp.size(), 0);
#endif
                            log_line("[conn] closed (bad login payload)");
                            closesock(client);
                            return;
                        }

                        std::string user = parse_asciiz32(f.payload, 0);
                        std::string pass = parse_asciiz32(f.payload, USER_PASS_FIELD);

                        // Define validity (adjust if your assignment specifies otherwise)
                        bool ok = (user == "testuser" && pass == "testpass");

                        ctx.user_sum  = checksum8_bytes(reinterpret_cast<const uint8_t*>(user.data()), user.size());
                        ctx.pass_sum  = checksum8_bytes(reinterpret_cast<const uint8_t*>(pass.data()), pass.size());
                        ctx.logged_in = ok;

                        {
                            std::ostringstream os;
                            os << "  login user=\"" << user << "\" user_sum=0x"
                               << std::hex << int(ctx.user_sum) << " pass_sum=0x" << int(ctx.pass_sum) << std::dec;
                            log_line(os.str());
                        }

                        std::vector<uint8_t> status(2, 0x00); // FAILED by default
                        if (ok) status[1] = 0x01;            // 0x0001 OK (big-endian)
                        auto resp = build_frame_be(MSG_LOGIN_RESP, f.message_sequence, status);
#ifdef _WIN32
                        send(client, reinterpret_cast<const char*>(resp.data()), (int)resp.size(), 0);
#else
                        send(client, resp.data(), (int)resp.size(), 0);
#endif

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
                        xor_with_lcg(seed, msg); // decrypt in-place → plaintext

                        // log plaintext (ascii if printable)
                        bool printable = !msg.empty();
                        for (auto b : msg) if (b < 32 || b > 126) { printable = false; break; }
                        if (printable) {
                            std::string s(msg.begin(), msg.end());
                            log_line(std::string("  decrypted ascii: \"") + s + "\"");
                        } else {
                            std::lock_guard<std::mutex> lk(g_log);
                            std::cout << "  decrypted hex: ";
                            hex_dump_locked(msg);
                        }

                        // Echo Response (type=3): BE16(len) + plaintext, same seq
                        std::vector<uint8_t> resp_payload(2 + msg.size());
                        put_be16(resp_payload.data(), (uint16_t)msg.size());
                        std::copy(msg.begin(), msg.end(), resp_payload.begin() + 2);

                        auto resp = build_frame_be(MSG_ECHO_RESP, f.message_sequence, resp_payload);
#ifdef _WIN32
                        int sent = send(client, reinterpret_cast<const char*>(resp.data()), (int)resp.size(), 0);
#else
                        int sent = send(client, resp.data(), (int)resp.size(), 0);
#endif
                        if (sent < 0) { log_line("[conn] send error; closing"); closesock(client); return; }
                        break;
                    }

                    default: {
                        // Unknown type: safe echo-back (same type/seq/payload)
                        auto echo = build_frame_be(f.message_type, f.message_sequence, f.payload);
#ifdef _WIN32
                        int sent = send(client, reinterpret_cast<const char*>(echo.data()), (int)echo.size(), 0);
#else
                        int sent = send(client, echo.data(), (int)echo.size(), 0);
#endif
                        if (sent < 0) { log_line("[conn] send error; closing"); closesock(client); return; }
                        break;
                    }
                } // switch
            } // for frames
        } catch (const std::exception& e) {
            std::ostringstream os; os << "[conn] parser error: " << e.what() << " — closing";
            log_line(os.str());
            break;
        }
    } // recv loop

    closesock(client);
    log_line("[conn] closed");
}

// ----- main accept loop -----
int main(int argc, char** argv) {
    uint16_t port = 5555;
    if (argc >= 2) port = static_cast<uint16_t>(std::stoi(argv[1]));

    net_init();

    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { std::cerr << "socket() failed\n"; net_cleanup(); return 1; }
    set_reuseaddr(s);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind() failed\n"; closesock(s); net_cleanup(); return 2;
    }
    if (listen(s, 128) < 0) {
        std::cerr << "listen() failed\n"; closesock(s); net_cleanup(); return 3;
    }

    std::cout << "[server] listening on 0.0.0.0:" << port << "\n";
    std::vector<std::thread> threads;

    for (;;) {
        sockaddr_in cli{}; socklen_t clilen = sizeof(cli);
        socket_t c = accept(s, reinterpret_cast<sockaddr*>(&cli), &clilen);
        if (c < 0) {
            std::cerr << "accept() error, continuing\n";
            continue;
        }
        threads.emplace_back(handle_connection, c);
        // Optional: detach to avoid storing/joining threads; left joined here for clarity.
    }

    for (auto& t : threads) if (t.joinable()) t.join();
    closesock(s);
    net_cleanup();
    return 0;
}
