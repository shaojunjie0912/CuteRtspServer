#include <chrono>        // 用于 std::chrono::*
#include <cstring>       // 用于 strerror
#include <format>        // 用于 std::format (C++20 格式化)
#include <iostream>      // 用于 cout, cerr
#include <sstream>       // 用于 std::istringstream (解析)
#include <stdexcept>     // 用于 std::runtime_error
#include <string>        // 用于 std::string
#include <system_error>  // 用于 std::system_error, std::errc
#include <thread>        // 用于 std::this_thread::sleep_for
#include <vector>        // 用于 std::vector (缓冲区)

// Linux/POSIX Socket 头文件
#include <arpa/inet.h>
#include <fcntl.h>  // 用于 fcntl (可选，例如设置非阻塞)
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>  // 用于 close, read, write, usleep (如果不用 C++ 线程库)

// 定义常量
constexpr int SERVER_PORT = 8554;
constexpr int SERVER_RTP_PORT = 55532;
constexpr int SERVER_RTCP_PORT = 55533;
constexpr int BUFFER_SIZE = 2048;  // 定义缓冲区大小

// --- 辅助函数 ---

// 抛出带有 errno 信息的系统错误
void throw_system_error(const std::string& msg) {
    throw std::system_error(errno, std::system_category(), msg);
}

// --- RTSP 命令处理函数 ---
// 返回响应字符串

std::string handleCmd_OPTIONS(int cseq) {
    // 使用 C++20 的 std::format
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
        "\r\n",
        cseq);
}

std::string handleCmd_DESCRIBE(int cseq, std::string_view url) {
    std::string sdp;
    std::string localIp = "127.0.0.1";  // 默认或从 url 解析

    // 尝试从 URL 解析 IP (简易方式，可能不健壮)
    // rtsp://192.168.1.10:8554/live
    size_t start = url.find("://");
    if (start != std::string_view::npos) {
        start += 3;  // 跳过 "://"
        size_t end = url.find(':', start);
        if (end == std::string_view::npos) {
            end = url.find('/', start);  // 如果没有端口，查找路径分隔符
        }
        if (end != std::string_view::npos) {
            localIp = std::string(url.substr(start, end - start));
        } else {
            // 如果也没有 '/'，则取到结尾
            localIp = std::string(url.substr(start));
        }
    } else {
        std::cerr << "Warning: Could not parse IP from URL: " << url << std::endl;
    }

    // 使用 time(nullptr) 获取时间戳
    // 注意：原始代码的 o=- 9%ld 1 ... 中的 9%ld 可能是笔误或特定格式
    // 这里使用 time(nullptr) 作为 session ID 和 version
    long session_id = time(nullptr);

    sdp = std::format(
        "v=0\r\n"
        "o=- {} 1 IN IP4 {}\r\n"  // 使用解析出的或默认的 IP
        "s=Unnamed Session\r\n"   // 添加一个会话名称
        "t=0 0\r\n"
        "a=control:*\r\n"
        "m=video 0 RTP/AVP 96\r\n"  // 端口 0 通常表示动态选择，但客户端可能需要具体端口
        "a=rtpmap:96 H264/90000\r\n"
        "a=control:track0\r\n",
        session_id, localIp);

    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Content-Base: {}\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: {}\r\n"
        "\r\n"
        "{}",
        cseq,
        std::string(url),  // Content-Base 通常是请求的 URL
        sdp.length(), sdp);
}

std::string handleCmd_SETUP(int cseq, int clientRtpPort) {
    // Session ID 应该是唯一的，这里硬编码了一个，实际应用中应动态生成和管理
    constexpr long SESSION_ID = 66334873;
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Transport: RTP/AVP/UDP;unicast;client_port={}-{};server_port={}-{}\r\n"
        "Session: {}\r\n"
        "\r\n",
        cseq, clientRtpPort, clientRtpPort + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT, SESSION_ID);
}

std::string handleCmd_PLAY(int cseq) {
    constexpr long SESSION_ID = 66334873;  // 与 SETUP 保持一致
    return std::format(
        "RTSP/1.0 200 OK\r\n"
        "CSeq: {}\r\n"
        "Range: npt=0.000-\r\n"
        "Session: {}; timeout=60\r\n"                         // 增加 timeout
        "RTP-Info: url=rtsp://{}/track0;seq=0;rtptime=0\r\n"  // 可选但常见的 RTP-Info
        "\r\n",
        cseq, SESSION_ID,
        "server-address:port"  // TODO: 替换为服务器的实际地址和 track ID
    );
}

// --- 客户端处理函数 ---
void doClient(int clientSockfd, const std::string& clientIP, int clientPort) {
    std::cout << "Handling client: " << clientIP << ":" << clientPort << std::endl;

    std::vector<char> rBuf(BUFFER_SIZE);
    std::string sBuf;  // 用于存储响应

    std::string method;
    std::string url;
    std::string version;
    int cseq = 0;
    int clientRtpPort = -1;
    int clientRtcpPort = -1;
    bool playing = false;  // 标记是否处于 PLAY 状态

    try {
        while (true) {
            // 重置解析状态
            method.clear();
            url.clear();
            version.clear();
            cseq = 0;
            // clientRtpPort, clientRtcpPort 通常在 SETUP 后保持不变

            ssize_t recvLen = recv(clientSockfd, rBuf.data(), rBuf.size() - 1, 0);

            if (recvLen < 0) {
                // EINTR 表示信号中断，可以重试
                if (errno == EINTR) continue;
                perror("recv failed");
                break;
            }
            if (recvLen == 0) {
                std::cout << "Client " << clientIP << ":" << clientPort << " disconnected."
                          << std::endl;
                break;
            }

            rBuf[recvLen] = '\0';  // 确保 C 风格字符串结束符 (虽然我们主要用 C++)
            std::string_view requestView(rBuf.data(), recvLen);

            std::cout << ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n";
            std::cout << "Received from " << clientIP << ":" << clientPort << ":\n"
                      << requestView << std::endl;

            // --- 解析 RTSP 请求 ---
            std::istringstream requestStream{std::string(requestView)};  // 从 string_view 创建流
            std::string line;

            // 解析请求行
            if (std::getline(requestStream, line) && !line.empty() && line.back() == '\r') {
                line.pop_back();  // 移除末尾的 \r
                std::istringstream lineStream(line);
                if (!(lineStream >> method >> url >> version)) {
                    std::cerr << "Error parsing request line: " << line << std::endl;
                    // 可以发送 400 Bad Request
                    break;
                }
            } else {
                std::cerr << "Error reading request line or empty request." << std::endl;
                break;
            }

            // 解析头部字段
            while (std::getline(requestStream, line) && !line.empty() && line != "\r") {
                if (line.back() == '\r') {
                    line.pop_back();  // 移除末尾的 \r
                }

                // 提取 CSeq
                if (line.starts_with("CSeq:")) {
                    try {
                        cseq = std::stoi(line.substr(5));  // 跳过 "CSeq:"
                    } catch (const std::invalid_argument& e) {
                        std::cerr << "Error parsing CSeq: " << line << std::endl;
                    } catch (const std::out_of_range& e) {
                        std::cerr << "CSeq out of range: " << line << std::endl;
                    }
                }
                // 提取 Transport (针对 SETUP)
                else if (method == "SETUP" && line.starts_with("Transport:")) {
                    std::string transport_header = line.substr(10);  // 跳过 "Transport:"
                    size_t port_pos = transport_header.find("client_port=");
                    if (port_pos != std::string::npos) {
                        // 尝试解析 client_port=rtp_port-rtcp_port
                        if (sscanf(transport_header.c_str() + port_pos, "client_port=%d-%d",
                                   &clientRtpPort, &clientRtcpPort) == 2) {
                            // 解析成功
                        }
                        // 尝试解析 client_port=rtp_port (可能没有 RTCP 端口)
                        else if (sscanf(transport_header.c_str() + port_pos, "client_port=%d",
                                        &clientRtpPort) == 1) {
                            clientRtcpPort = clientRtpPort + 1;  // 假设 RTCP 紧随其后
                        } else {
                            std::cerr
                                << "Error parsing client_port in Transport: " << transport_header
                                << std::endl;
                            clientRtpPort = -1;  // 标记解析失败
                        }
                    } else {
                        std::cerr << "Could not find client_port in Transport: " << transport_header
                                  << std::endl;
                    }
                }
                // 可以添加对其他头部的解析，如 Session (用于 PLAY, TEARDOWN 等)
            }

            // --- 根据方法生成响应 ---
            if (method == "OPTIONS") {
                sBuf = handleCmd_OPTIONS(cseq);
            } else if (method == "DESCRIBE") {
                sBuf = handleCmd_DESCRIBE(cseq, url);
            } else if (method == "SETUP") {
                if (clientRtpPort != -1) {
                    sBuf = handleCmd_SETUP(cseq, clientRtpPort);
                } else {
                    // 发送错误响应，例如 461 Unsupported Transport
                    sBuf = std::format(
                        "RTSP/1.0 461 Unsupported Transport\r\n"
                        "CSeq: {}\r\n"
                        "\r\n",
                        cseq);
                    std::cerr << "SETUP failed: Could not parse client_port" << std::endl;
                }
            } else if (method == "PLAY") {
                sBuf = handleCmd_PLAY(cseq);
                playing = true;  // 标记进入 PLAY 状态
            }
            // TODO: 添加 TEARDOWN 等其他方法的处理
            // else if (method == "TEARDOWN") { ... }
            else {
                std::cerr << "Unsupported method: " << method << std::endl;
                // 发送 501 Not Implemented 或 405 Method Not Allowed
                sBuf = std::format(
                    "RTSP/1.0 405 Method Not Allowed\r\n"
                    "CSeq: {}\r\n"
                    "Allow: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"  // 列出支持的方法
                    "\r\n",
                    cseq);
            }

            // --- 发送响应 ---
            std::cout << "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n";
            std::cout << "Sending to " << clientIP << ":" << clientPort << ":\n"
                      << sBuf << std::endl;
            ssize_t sendLen = send(clientSockfd, sBuf.c_str(), sBuf.length(), 0);
            if (sendLen < 0) {
                perror("send failed");
                break;
            }
            if (sendLen != static_cast<ssize_t>(sBuf.length())) {
                std::cerr << "Warning: Incomplete send." << std::endl;
            }

            // --- 如果是 PLAY 请求，开始模拟发送 RTP 数据 ---
            if (playing) {
                std::cout << "===> Start 'streaming' (simulation) for client " << clientIP << ":"
                          << clientRtpPort << std::endl;

                // **注意:** 这里的循环只是模拟时间流逝，并没有真正实现 RTP 打包和发送。
                // 一个真实的 RTSP 服务器需要在这里:
                // 1. 创建 UDP socket 用于发送 RTP (和 RTCP)。
                // 2. 连接到客户端指定的 RTP/RTCP 端口 (clientRtpPort, clientRtcpPort)。
                // 3. 读取 H.264 (或其他格式) 的视频帧。
                // 4. 将视频帧按照 RFC 3984 (H.264 RTP) 或其他相应 RFC 进行打包。
                // 5. 添加 RTP 头部 (序列号、时间戳等)。
                // 6. 通过 UDP socket 发送 RTP 包。
                // 7. (可选) 发送 RTCP Sender Reports。
                // 8. 处理客户端的 RTCP Receiver Reports。
                // 9. 处理 TEARDOWN 请求以停止流。

                // 简单的模拟循环，等待一段时间后退出 (实际应用中需要根据流状态或 TEARDOWN 退出)
                int simulated_packets = 0;
                while (simulated_packets < 100) {  // 模拟发送 100 个包
                    // 检查客户端是否仍然连接 (尝试读取少量数据，非阻塞或带超时)
                    // poll 或 select 可以用来检测连接是否断开或是否有 TEARDOWN 请求
                    char peek_buf[1];
                    ssize_t peek_len = recv(clientSockfd, peek_buf, 1, MSG_DONTWAIT | MSG_PEEK);
                    if (peek_len == 0) {  // 客户端断开
                        std::cout << "Client disconnected during streaming." << std::endl;
                        playing = false;
                        break;
                    }
                    if (peek_len < 0 && (errno != EAGAIN && errno != EWOULDBLOCK)) {  // 读取错误
                        perror("recv peek failed during streaming");
                        playing = false;
                        break;
                    }
                    // 如果 peek_len > 0，可能收到了 TEARDOWN，需要读取并处理

                    std::cout << "Simulating sending RTP packet " << simulated_packets + 1 << "..."
                              << std::endl;
                    // 模拟帧率 (例如 25fps -> 40ms 间隔)
                    std::this_thread::sleep_for(std::chrono::milliseconds(40));
                    simulated_packets++;
                }

                std::cout << "===> Finished 'streaming' simulation." << std::endl;
                // 在这个简单示例中，模拟结束后就退出客户端处理循环
                break;  // 退出 doClient 循环
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in doClient for " << clientIP << ":" << clientPort << ": "
                  << e.what() << std::endl;
    }

    // --- 清理 ---
    close(clientSockfd);
    std::cout << "Closed connection for " << clientIP << ":" << clientPort << std::endl;
}

// --- 主函数 ---
int main() {
    int serverSockfd = -1;  // 初始化为无效值

    try {
        // 1. 创建 TCP Socket
        serverSockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSockfd < 0) {
            throw_system_error("Failed to create socket");
        }

        // 2. 设置 SO_REUSEADDR 选项 (允许快速重启服务器绑定相同地址)
        int on = 1;
        if (setsockopt(serverSockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            // 通常不认为是致命错误，但最好记录下来
            perror("setsockopt(SO_REUSEADDR) failed");
        }
        // 可以选择设置 SO_REUSEPORT (允许多个进程绑定相同端口)
        // if (setsockopt(serverSockfd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0) {
        //     perror("setsockopt(SO_REUSEPORT) failed");
        // }

        // 3. 绑定地址和端口
        struct sockaddr_in serverAddr;
        memset(&serverAddr, 0, sizeof(serverAddr));  // 清零结构体
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(SERVER_PORT);
        serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);  // 绑定到所有网络接口

        if (bind(serverSockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            throw_system_error("Failed to bind socket");
        }

        // 4. 开始监听
        if (listen(serverSockfd, SOMAXCONN) < 0) {  // 使用 SOMAXCONN 作为 backlog
            throw_system_error("Failed to listen on socket");
        }

        std::cout << std::format("RTSP server listening on rtsp://127.0.0.1:{}", SERVER_PORT)
                  << std::endl;

        // 5. 接受客户端连接循环
        while (true) {
            struct sockaddr_in clientAddr;
            socklen_t clientAddrLen = sizeof(clientAddr);
            int clientSockfd = -1;

            clientSockfd = accept(serverSockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);

            if (clientSockfd < 0) {
                // EINTR 表示信号中断，可以继续循环
                if (errno == EINTR) continue;
                perror("Failed to accept client connection");
                // 可以选择继续接受下一个连接，或者在严重错误时退出
                continue;  // 继续等待下一个连接
            }

            // 获取客户端 IP 和端口信息
            char clientIpStr[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, sizeof(clientIpStr)) ==
                nullptr) {
                perror("inet_ntop failed");
                strncpy(clientIpStr, "Unknown", sizeof(clientIpStr) - 1);
                clientIpStr[sizeof(clientIpStr) - 1] = '\0';
            }
            int clientPort = ntohs(clientAddr.sin_port);

            std::cout << std::format("Accepted connection from {}:{}", clientIpStr, clientPort)
                      << std::endl;

            // 处理客户端请求 (这里是串行处理，可以改为多线程或异步)
            try {
                doClient(clientSockfd, clientIpStr, clientPort);
            } catch (const std::exception& e) {
                std::cerr << "Unhandled exception during client handling: " << e.what()
                          << std::endl;
                // 确保即使内部异常也关闭 socket
                close(clientSockfd);
            } catch (...) {
                std::cerr << "Unknown unhandled exception during client handling." << std::endl;
                close(clientSockfd);
            }
            // 注意：doClient 函数内部会 close(clientSockfd)
        }

    } catch (const std::system_error& e) {
        std::cerr << "System Error: " << e.what() << " (Code: " << e.code() << ")" << std::endl;
        if (serverSockfd >= 0) {
            close(serverSockfd);  // 确保关闭监听 socket
        }
        return 1;  // 返回错误码
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        if (serverSockfd >= 0) {
            close(serverSockfd);
        }
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred." << std::endl;
        if (serverSockfd >= 0) {
            close(serverSockfd);
        }
        return 1;
    }

    // 正常情况下不会执行到这里，除非循环被中断
    if (serverSockfd >= 0) {
        close(serverSockfd);
        std::cout << "Server socket closed." << std::endl;
    }

    return 0;
}