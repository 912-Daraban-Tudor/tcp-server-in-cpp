// src/client_demo.cpp
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socket_t = SOCKET;
static void net_init() { WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa); }
static void net_cleanup() { WSACleanup(); }
static void closesock(socket_t s) { closesocket(s); }
#else
#include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  using socket_t = int;
  static void net_init() {}
  static void net_cleanup() {}
  static void closesock(socket_t s) { close(s); }
#endif

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

int main(int argc, char** argv) {
    const char* host = (argc >= 2) ? argv[1] : "127.0.0.1";
    uint16_t port = (argc >= 3) ? static_cast<uint16_t>(std::stoi(argv[2])) : 5555;

    net_init();

    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { std::cerr << "socket() failed\n"; net_cleanup(); return 1; }

    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
#ifdef _WIN32
    inet_pton(AF_INET, host, &addr.sin_addr);
#else
    inet_aton(host, &addr.sin_addr);
#endif
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "connect() failed\n"; closesock(s); net_cleanup(); return 2;
    }

    auto frame = build_frame_be(1, 5, std::vector<uint8_t>{'H','e','l','l','o'});
#ifdef _WIN32
    int sent = send(s, reinterpret_cast<const char*>(frame.data()), (int)frame.size(), 0);
#else
    int sent = send(s, frame.data(), (int)frame.size(), 0);
#endif
    if (sent < 0) { std::cerr << "send error\n"; closesock(s); net_cleanup(); return 3; }

    std::vector<uint8_t> rx(1024);
#ifdef _WIN32
    int n = recv(s, reinterpret_cast<char*>(rx.data()), (int)rx.size(), 0);
#else
    int n = recv(s, rx.data(), (int)rx.size(), 0);
#endif
    if (n > 0) {
        std::cout << "Received " << n << " bytes back (echo): ";
        for (int i = 0; i < n; ++i)
            std::cout << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << int(rx[i]) << " ";
        std::cout << std::dec << "\n";
    } else {
        std::cout << "No echo received.\n";
    }

    closesock(s);
    net_cleanup();
    return 0;
}
