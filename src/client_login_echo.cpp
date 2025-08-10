// client_login_echo.cpp — Linux-only, spec-correct, CLI-polished
// Usage:
//   ./client_login_echo [host] [port] --user=U --pass=P --msg="Hello" --seq=2
// Defaults:
//   host=127.0.0.1 port=5555 user=testuser pass=testpass msg="Hello from client" seq=2

#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <csignal>
#include <sys/time.h>
#include <getopt.h>

#include "protocol.h"
#include "crypto_lcg.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using socket_t = int;

static void closesock(socket_t s){ if (s >= 0) ::close(s); }

static void usage(const char* prog){
    std::cerr <<
              "Usage: " << prog << " [host] [port] [--user=U] [--pass=P] [--msg=M] [--seq=N]\n"
                                   "Defaults: host=127.0.0.1 port=5555 user=testuser pass=testpass msg=\"Hello from client\" seq=2\n";
}

// --- helpers ---------------------------------------------------------------
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
static bool recv_all(socket_t s, uint8_t* p, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = ::recv(s, p + got, n - got, 0);
        if (k <= 0) return false;
        got += static_cast<size_t>(k);
    }
    return true;
}

static std::vector<uint8_t> build_frame_be(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload){
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

static std::vector<uint8_t> build_login_payload(const std::string& user, const std::string& pass){
    std::vector<uint8_t> p(USER_PASS_FIELD * 2, 0);
    std::memcpy(p.data(), user.data(), std::min(user.size(), USER_PASS_FIELD - 1));
    std::memcpy(p.data() + USER_PASS_FIELD, pass.data(), std::min(pass.size(), USER_PASS_FIELD - 1));
    return p;
}

// Read one framed message from the socket into (type, seq, payload)
static bool read_frame(socket_t s, uint8_t& type, uint8_t& seq, std::vector<uint8_t>& payload) {
    uint8_t hdr[4];
    if (!recv_all(s, hdr, 4)) return false;
    uint16_t msg_size = (uint16_t(hdr[0]) << 8) | uint16_t(hdr[1]);
    if (msg_size < 4) return false;
    type = hdr[2];
    seq  = hdr[3];
    size_t payload_len = msg_size - 4;
    payload.resize(payload_len);
    if (payload_len && !recv_all(s, payload.data(), payload_len)) return false;
    return true;
}

int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);

    // defaults
    std::string user = "testuser";
    std::string pass = "testpass";
    std::string plaintext = "Hello from client";
    int seq_echo = 2;
    uint8_t seq_login = 1;

    // parse long options
    static option opts[] = {
            {"user", required_argument, nullptr, 'u'},
            {"pass", required_argument, nullptr, 'p'},
            {"msg",  required_argument, nullptr, 'm'},
            {"seq",  required_argument, nullptr, 's'},
            {nullptr,0,nullptr,0}
    };
    int opt, idx;
    // allow host/port as positional; getopt_long will leave them in argv[optind..]
    while ((opt = getopt_long(argc, argv, "", opts, &idx)) != -1) {
        switch (opt) {
            case 'u': user = optarg; break;
            case 'p': pass = optarg; break;
            case 'm': plaintext = optarg; break;
            case 's': try { seq_echo = std::stoi(optarg); } catch (...) { usage(argv[0]); return 1; } break;
            default: usage(argv[0]); return 1;
        }
    }

    const char* host = "127.0.0.1";
    uint16_t port = 5555;
    if (optind < argc) host = argv[optind++];
    if (optind < argc) {
        try { port = static_cast<uint16_t>(std::stoi(argv[optind++])); }
        catch (...) { usage(argv[0]); return 1; }
    }

    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { std::cerr << "socket() failed\n"; return 1; }

    // timeouts + low latency
    timeval tv{10, 0}; // 10s
    ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1; ::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    if (::inet_aton(host, &addr.sin_addr) == 0) { std::cerr << "bad host\n"; closesock(s); return 2; }

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("connect");
        std::cerr << "connect() failed\n"; closesock(s); return 3;
    }

    // --- 1) Login -----------------------------------------------------------
    auto login_payload = build_login_payload(user, pass);
    auto login_frame   = build_frame_be(MSG_LOGIN_REQ, seq_login, login_payload);

    if (!send_all(s, login_frame.data(), login_frame.size())) {
        std::cerr << "send(login) failed\n"; closesock(s); return 4;
    }

    uint8_t rtype=0, rseq=0; std::vector<uint8_t> rpay;
    if (!read_frame(s, rtype, rseq, rpay)) {
        std::cerr << "recv(login resp) failed\n"; closesock(s); return 5;
    }
    if (rtype != MSG_LOGIN_RESP || rpay.size() < 2) {
        std::cerr << "bad login response\n"; closesock(s); return 6;
    }
    uint16_t status = be16(rpay.data());
    std::cout << "[client] login status=" << (status == 1 ? "OK" : "FAILED") << " (seq=" << int(rseq) << ")\n";
    if (status != 1) { closesock(s); return 0; }

    // --- 2) Echo (encrypt per spec) ----------------------------------------
    std::vector<uint8_t> cipher(plaintext.begin(), plaintext.end());

    uint8_t user_sum = checksum8_str_ascii(user);
    uint8_t pass_sum = checksum8_str_ascii(pass);

    if (seq_echo < 0 || seq_echo > 255) { std::cerr << "--seq must be 0..255\n"; closesock(s); return 1; }
    uint8_t seq_echo_u8 = static_cast<uint8_t>(seq_echo);

    uint32_t seed = (uint32_t(seq_echo_u8) << 16) | (uint32_t(user_sum) << 8) | uint32_t(pass_sum);
    xor_with_lcg(seed, cipher); // encrypt in-place

    // Echo Request payload: BE16(cipher_len) + cipher bytes
    std::vector<uint8_t> echo_payload(2 + cipher.size());
    put_be16(echo_payload.data(), static_cast<uint16_t>(cipher.size()));
    std::memcpy(echo_payload.data() + 2, cipher.data(), cipher.size());

    auto echo_frame = build_frame_be(MSG_ECHO_REQ, seq_echo_u8, echo_payload);
    if (!send_all(s, echo_frame.data(), echo_frame.size())) {
        std::cerr << "send(echo) failed\n"; closesock(s); return 7;
    }

    // --- 3) Echo Response (plaintext) --------------------------------------
    if (!read_frame(s, rtype, rseq, rpay)) {
        std::cerr << "recv(echo resp) failed\n"; closesock(s); return 8;
    }
    if (rtype != MSG_ECHO_RESP || rpay.size() < 2) {
        std::cerr << "bad echo response\n"; closesock(s); return 9;
    }
    uint16_t plain_len = be16(rpay.data());
    if (plain_len > rpay.size() - 2) {
        std::cerr << "echo resp length mismatch\n"; closesock(s); return 10;
    }
    std::string plain(reinterpret_cast<const char*>(rpay.data() + 2), plain_len);
    std::cout << "[client] echo plaintext (seq=" << int(rseq) << "): \"" << plain << "\"\n";

    closesock(s);
    return 0;
}
