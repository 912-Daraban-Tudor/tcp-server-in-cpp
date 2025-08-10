#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstring>

#include "protocol.h"
#include "crypto_lcg.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
static void net_init(){ WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa); }
static void net_cleanup(){ WSACleanup(); }
static void closesock(socket_t s){ closesocket(s); }
#else
#include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  using socket_t = int;
  static void net_init() {}
  static void net_cleanup() {}
  static void closesock(socket_t s){ close(s); }
#endif

static std::vector<uint8_t> build_frame_be(uint8_t type, uint8_t seq, const std::vector<uint8_t>& payload){
    auto size = uint16_t(4 + payload.size());
    std::vector<uint8_t> out;
    out.reserve(size);
    out.push_back(uint8_t((size >> 8) & 0xFF));
    out.push_back(uint8_t(size & 0xFF));
    out.push_back(type);
    out.push_back(seq);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

static std::vector<uint8_t> build_login_payload(const std::string& user, const std::string& pass){
    std::vector<uint8_t> p; p.resize(USER_PASS_FIELD * 2, 0);
    // copy user (truncate if longer than 31 to leave room for 0 terminator; but spec says fixed ASCIIZ in 32 bytes)
    size_t ulen = std::min(user.size(), USER_PASS_FIELD - 1);
    std::memcpy(p.data(), user.data(), ulen);
    // copy pass
    size_t plen = std::min(pass.size(), USER_PASS_FIELD - 1);
    std::memcpy(p.data() + USER_PASS_FIELD, pass.data(), plen);
    return p;
}

int main(int argc, char** argv){
    const char* host = (argc >= 2) ? argv[1] : "127.0.0.1";
    uint16_t port = (argc >= 3) ? static_cast<uint16_t>(std::stoi(argv[2])) : 5555;

    net_init();

    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { std::cerr << "socket() failed\n"; return 1; }

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
#ifdef _WIN32
    inet_pton(AF_INET, host, &addr.sin_addr);
#else
    inet_aton(host, &addr.sin_addr);
#endif
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "connect() failed\n"; closesock(s); net_cleanup(); return 2;
    }

    // 1) Send Login
    std::string user = "testuser";
    std::string pass = "testpass";
    uint8_t seq_login = 1;

    auto login_payload = build_login_payload(user, pass);
    auto login_frame = build_frame_be(MSG_LOGIN_REQ, seq_login, login_payload);

#ifdef _WIN32
    int sent = send(s, reinterpret_cast<const char*>(login_frame.data()), (int)login_frame.size(), 0);
#else
    int sent = send(s, login_frame.data(), (int)login_frame.size(), 0);
#endif
    if (sent < 0) { std::cerr << "send(login) error\n"; closesock(s); net_cleanup(); return 3; }

    // Receive login ACK (optional read)
    std::vector<uint8_t> rx(1024);
#ifdef _WIN32
    int n = recv(s, reinterpret_cast<char*>(rx.data()), (int)rx.size(), 0);
#else
    int n = recv(s, rx.data(), (int)rx.size(), 0);
#endif
    if (n > 0) {
        std::cout << "Login response (" << n << " bytes): ";
        for (int i = 0; i < n; ++i)
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << int(rx[i]) << " ";
        std::cout << std::dec << "\n";
    }

    // 2) Send encrypted Echo for plaintext "Hello from client"
    std::string plaintext = "Hello from client";
    std::vector<uint8_t> cipher(plaintext.begin(), plaintext.end());

    // Compute sums like server does
    uint8_t user_sum = checksum8_str_ascii(user);
    uint8_t pass_sum = checksum8_str_ascii(pass);

    uint8_t seq_echo = 2; // any byte; server will use this in seed
    uint32_t seed = (uint32_t(seq_echo) << 16) | (uint32_t(user_sum) << 8) | uint32_t(pass_sum);

    xor_with_lcg(seed, cipher); // encrypt in-place

    auto echo_frame = build_frame_be(MSG_ECHO_REQ, seq_echo, cipher);
#ifdef _WIN32
    sent = send(s, reinterpret_cast<const char*>(echo_frame.data()), (int)echo_frame.size(), 0);
#else
    sent = send(s, echo_frame.data(), (int)echo_frame.size(), 0);
#endif
    if (sent < 0) { std::cerr << "send(echo) error\n"; closesock(s); net_cleanup(); return 4; }

    // Read echo ACK (ciphertext echoed back)
#ifdef _WIN32
    n = recv(s, reinterpret_cast<char*>(rx.data()), (int)rx.size(), 0);
#else
    n = recv(s, rx.data(), (int)rx.size(), 0);
#endif
    if (n > 0) {
        std::cout << "Echo response (" << n << " bytes): ";
        for (int i = 0; i < n; ++i)
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << int(rx[i]) << " ";
        std::cout << std::dec << "\n";
    } else {
        std::cout << "No echo response\n";
    }

    closesock(s);
    net_cleanup();
    return 0;
}
