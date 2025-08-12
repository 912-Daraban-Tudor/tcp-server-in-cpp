#include <vector>
#include <string>
#include <iostream>
#include <cstring>
#include <csignal>
#include <getopt.h>

#include "wire.h"
#include "crypto_lcg.h"

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using socket_t = int;

constexpr uint16_t DEFAULT_PORT = 5555;

// helpers
namespace {
    void close_fd(socket_t s) noexcept {
        if (s >= 0)
            ::close(s);
    }

    void usage(const char* prog) {
        std::cerr
                << "Usage: " << prog << " [host] [port] [--user=U] [--pass=P] [--msg=M] [--seq=N]\n"
                << "Defaults: host=127.0.0.1 port=5555 user=testuser pass=testpass msg=\"Hello from client\" seq=2\n";
    }

// TCP can short-write, loop until all sent. Treat EAGAIN/EWOULDBLOCK as timeout/failure.
    bool send_all(socket_t s, const uint8_t* p, size_t n) {
        while (n) {
            const ssize_t k = ::send(s, p, n, 0);
            if (k > 0) {
                p += static_cast<size_t>(k);
                n -= static_cast<size_t>(k);
                continue;
            }
            if (k < 0 && errno == EINTR)
                continue;
            return false; // timeout/EPIPE/other
        }
        return true;
    }

    bool recv_all(socket_t s, uint8_t* p, size_t n) {
        size_t got = 0;
        while (got < n) {
            const ssize_t k = ::recv(s, p + got, n - got, 0);
            if (k > 0) {
                got += static_cast<size_t>(k);
                continue;
            }
            if (k < 0 && errno == EINTR)
                continue;
            return false; // timeout/closed/other
        }
        return true;
    }

// Read one framed message: fills type/seq/payload; returns false on failure.
    bool read_frame(socket_t s, uint8_t& type, uint8_t& seq, std::vector<uint8_t>& payload) {
        uint8_t hdr[PROTO_HEADER_SIZE];
        if (!recv_all(s, hdr, PROTO_HEADER_SIZE))
            return false;

        const uint16_t msg_size = be16(hdr);
        if (msg_size < PROTO_HEADER_SIZE)
            return false;

        type = hdr[2];
        seq  = hdr[3];

        const size_t payload_len = msg_size - PROTO_HEADER_SIZE;
        payload.resize(payload_len);
        if (payload_len && !recv_all(s, payload.data(), payload_len))
            return false;
        return true;
    }
} // namespace

int main(int argc, char** argv) {
    ::signal(SIGPIPE, SIG_IGN); // Linux-only: avoid SIGPIPE on send

    // Defaults, overridable via CLI
    std::string user      = "user";
    std::string pass      = "password";
    std::string plaintext = "client for the tcp server";
    int         seq_echo  = 2;
    const uint8_t seq_login = 1;

    // Parse long options first, host/port remain positional
    static option opts[] = {
            {"user", required_argument, nullptr, 'u'},
            {"pass", required_argument, nullptr, 'p'},
            {"msg",  required_argument, nullptr, 'm'},
            {"seq",  required_argument, nullptr, 's'},
            {nullptr,0,nullptr,0}
    };
    int opt = 0, idx = 0;
    while ((opt = ::getopt_long(argc, argv, "", opts, &idx)) != -1) {
        switch (opt) {
            case 'u': user = optarg; break;
            case 'p': pass = optarg; break;
            case 'm': plaintext = optarg; break;
            case 's':
                try {
                    seq_echo = std::stoi(optarg);
                } catch (...) {
                    usage(argv[0]);
                    return 1;
                }
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    const char* host = "127.0.0.1";
    uint16_t port = DEFAULT_PORT;
    if (optind < argc) host = argv[optind++];
    if (optind < argc) {
        try {
            unsigned long p = std::stoul(argv[optind++]);
            if (p > 65535)
                throw std::out_of_range("port");
            port = static_cast<uint16_t>(p);
        } catch (...) {
            usage(argv[0]);
            return 1;
        }
    }

    socket_t s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        std::perror("socket");
        return 1;
    }

    // Timeouts + low latency (best effort)
    const timeval tv{10, 0}; // 10s
    (void)::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int one = 1;
    (void)::setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));


    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        std::cerr << "bad IPv4 address\n";
        close_fd(s);
        return 2;
    }

    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::perror("connect");
        close_fd(s);
        return 3;
    }

    // --- 1) Login ----
    std::vector<uint8_t> login_payload(USER_PASS_FIELD * 2);
    write_asciiz32(std::span<uint8_t, USER_PASS_FIELD>(login_payload.data(), USER_PASS_FIELD), user);
    write_asciiz32(std::span<uint8_t, USER_PASS_FIELD>(login_payload.data() + USER_PASS_FIELD, USER_PASS_FIELD), pass);

    const auto login_frame = build_frame(MSG_LOGIN_REQ, seq_login, login_payload);
    if (!send_all(s, login_frame.data(), login_frame.size())) {
        std::cerr << "send(login) failed\n";
        close_fd(s);
        return 4;
    }

    uint8_t rtype = 0;
    uint8_t rseq = 0;
    std::vector<uint8_t> rpay;
    if (!read_frame(s, rtype, rseq, rpay)) {
        std::cerr << "recv(login resp) failed\n";
        close_fd(s);
        return 5;
    }
    if (rtype != MSG_LOGIN_RESP || rpay.size() < 2) {
        std::cerr << "bad login response\n";
        close_fd(s);
        return 6;
    }
    const uint16_t status = be16(rpay.data());
    std::cout << "[client] login status=" << (status == 1 ? "OK" : "FAILED")
              << " (seq=" << int(rseq) << ")\n";
    if (status != 1) {
        close_fd(s);
        return 11;
    } // non-zero on failure

    // --- 2) Echo (encrypt per spec) -----
    if (seq_echo < 0 || seq_echo > 255) {
        std::cerr << "--seq must be 0..255\n";
        close_fd(s);
        return 1;
    }
    const uint8_t seq_echo_u8 = static_cast<uint8_t>(seq_echo);

    std::vector<uint8_t> cipher(plaintext.begin(), plaintext.end());
    const uint8_t  user_sum = checksum8_str_ascii(user);
    const uint8_t  pass_sum = checksum8_str_ascii(pass);
    const uint32_t seed = compute_seed(seq_echo_u8, user_sum, pass_sum);

    if (!cipher.empty())
        xor_with_lcg_inplace(seed, cipher.data(), cipher.size());

    // EchoReq payload = BE16(cipher_len) + cipher
    std::vector<uint8_t> echo_payload(2 + cipher.size());
    put_be16(echo_payload.data(), static_cast<uint16_t>(cipher.size()));

    if (!cipher.empty())
        std::memcpy(echo_payload.data() + 2, cipher.data(), cipher.size());

    const auto echo_frame = build_frame(MSG_ECHO_REQ, seq_echo_u8, echo_payload);
    if (!send_all(s, echo_frame.data(), echo_frame.size())) {
        std::cerr << "send(echo) failed\n";
        close_fd(s);
        return 7;
    }

    // --- 3) Echo Response plaintext -----
    if (!read_frame(s, rtype, rseq, rpay)) {
        std::cerr << "recv(echo resp) failed\n";
        close_fd(s);
        return 8;
    }
    if (rtype != MSG_ECHO_RESP || rpay.size() < 2) {
        std::cerr << "bad echo response\n";
        close_fd(s);
        return 9;
    }
    const uint16_t plain_len = be16(rpay.data());
    if (plain_len > rpay.size() - 2) {
        std::cerr << "echo resp length mismatch\n";
        close_fd(s);
        return 10;
    }

    const std::string plain(reinterpret_cast<const char*>(rpay.data() + 2), plain_len);
    std::cout << "[client] echo plaintext (seq=" << int(rseq) << "): \"" << plain << "\"\n";

    close_fd(s);
    return 0;
}
