#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <format>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

constexpr int SERVER_PORT = 8554;
constexpr int SERVER_RTP_PORT = 55532;
constexpr int SERVER_RTCP_PORT = 55533;
constexpr size_t BUFFER_SIZE = 4096;

enum class RTSPMethod { OPTIONS, DESCRIBE, SETUP, PLAY, UNKNOWN };

RTSPMethod parseMethod(const std::string& m) {
    if (m == "OPTIONS") return RTSPMethod::OPTIONS;
    if (m == "DESCRIBE") return RTSPMethod::DESCRIBE;
    if (m == "SETUP") return RTSPMethod::SETUP;
    if (m == "PLAY") return RTSPMethod::PLAY;
    return RTSPMethod::UNKNOWN;
}

int createServerSocket() {
    int sockfd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) throw std::system_error(errno, std::system_category(), "socket");
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(sockfd);
        throw std::system_error(errno, std::system_category(), "setsockopt");
    }
    return sockfd;
}

std::string handleOPTIONS(int cseq) {
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
        "\r\n",
        cseq);
}

std::string handleDESCRIBE(int cseq, const std::string& url) {
    // extract host from URL: rtsp://<host>:...
    std::string host;
    std::string prefix = "rtsp://";
    auto pos = url.find(prefix);
    if (pos != std::string::npos) {
        pos += prefix.size();
        auto colon = url.find(':', pos);
        if (colon != std::string::npos)
            host = url.substr(pos, colon - pos);
        else {
            auto slash = url.find('/', pos);
            host = url.substr(pos, slash - pos);
        }
    }
    std::time_t now = std::time(nullptr);
    std::string sdp = std::format(
        "v=0\r\n"
        "o=- 9{} 1 IN IP4 {}\r\n"
        "t=0 0\r\n"
        "a=control:*\r\n"
        "m=video 0 RTP/AVP 96\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=control:track0\r\n",
        now, host);
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Content-Base: {}\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: {}\r\n"
        "\r\n"
        "{}",
        cseq, url, sdp.size(), sdp);
}

std::string handleSETUP(int cseq, int clientRtpPort) {
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Transport: RTP/AVP;unicast;client_port={}-{};server_port={}-{}\r\n"
        "Session: 66334873\r\n"
        "\r\n",
        cseq, clientRtpPort, clientRtpPort + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT);
}

std::string handlePLAY(int cseq) {
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Range: npt=0.000-\r\n"
        "Session: 66334873; timeout=10\r\n"
        "\r\n",
        cseq);
}

void clientHandler(int clientSock, std::string clientIp, int clientPort) {
    std::vector<char> buffer(BUFFER_SIZE);
    while (true) {
        ssize_t len = recv(clientSock, buffer.data(), buffer.size(), 0);
        if (len <= 0) break;
        std::string req(buffer.data(), len);
        std::istringstream ss(req);
        std::string line, methodStr, url, version;
        int cseq = 0;
        int clientRtpPort = 0, clientRtcpPort = 0;

        while (std::getline(ss, line)) {
            if (line.rfind("OPTIONS", 0) == 0 || line.rfind("DESCRIBE", 0) == 0 ||
                line.rfind("SETUP", 0) == 0 || line.rfind("PLAY", 0) == 0) {
                std::istringstream ls(line);
                ls >> methodStr >> url >> version;
            } else if (line.rfind("CSeq:", 0) == 0) {
                cseq = std::stoi(line.substr(5));
            } else if (line.rfind("Transport:", 0) == 0) {
                auto p = line.find("client_port=");
                if (p != std::string::npos) {
                    p += 12;
                    clientRtpPort = std::stoi(line.substr(p));
                    auto dash = line.find('-', p);
                    if (dash != std::string::npos)
                        clientRtcpPort = std::stoi(line.substr(dash + 1));
                }
            }
        }

        auto method = parseMethod(methodStr);
        std::string resp;
        switch (method) {
            case RTSPMethod::OPTIONS:
                resp = handleOPTIONS(cseq);
                break;
            case RTSPMethod::DESCRIBE:
                resp = handleDESCRIBE(cseq, url);
                break;
            case RTSPMethod::SETUP:
                resp = handleSETUP(cseq, clientRtpPort);
                break;
            case RTSPMethod::PLAY:
                resp = handlePLAY(cseq);
                break;
            default:
                std::cerr << "Unknown method: " << methodStr << std::endl;
                return;
        }

        send(clientSock, resp.c_str(), resp.size(), 0);

        if (method == RTSPMethod::PLAY) {
            std::cout << "Streaming to " << clientIp << ':' << clientRtpPort << std::endl;
            // Dummy RTP send loop
            while (true) {
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
                // TODO: send RTP packets via UDP
            }
            break;
        }
    }
    ::shutdown(clientSock, SHUT_RDWR);
    ::close(clientSock);
}

int main() {
    // Ignore SIGPIPE to prevent crashes on send to closed sockets
    std::signal(SIGPIPE, SIG_IGN);

    int serverSock = createServerSocket();

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(serverSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    if (listen(serverSock, /*backlog=*/10) < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }

    std::cout << "RTSP server listening on rtsp://127.0.0.1:" << SERVER_PORT << "\n";

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);
        int clientSock = accept(serverSock, reinterpret_cast<sockaddr*>(&clientAddr), &len);
        if (clientSock < 0) {
            perror("accept");
            continue;
        }
        std::string clientIp = inet_ntoa(clientAddr.sin_addr);
        int clientPort = ntohs(clientAddr.sin_port);
        std::cout << "Accepted connection from " << clientIp << ':' << clientPort << std::endl;
        std::thread(clientHandler, clientSock, clientIp, clientPort).detach();
    }

    ::close(serverSock);
    return 0;
}
