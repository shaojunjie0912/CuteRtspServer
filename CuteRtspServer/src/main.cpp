#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cutertspserver/rtp.hpp>
#include <string>
#include <thread>

#define H264_FILE_NAME "/home/sjj/Workspace/CuteRtspServer/data/k-on.h264"
#define SERVER_PORT 8554
#define SERVER_RTP_PORT 55532
#define SERVER_RTCP_PORT 55533
#define BUF_MAX_SIZE (1024 * 1024)

int createTcpSocket();

int createUdpSocket();

int bindSocketAddr(int sockfd, const char* ip, int port);

// 接受客户端 TCP 连接请求, 并获取客户端的 IP 和端口号
int acceptClient(int sockfd, char* ip, int* port);

bool startCode3(const char* buf);

bool startCode4(const char* buf);

char* findNextStartCode(char* buf, int len);

int getFrameFromH264File(FILE* fp, char* frame, int size);

int rtpSendH264Frame(int serverRtpSockfd, const char* ip, int16_t port, RtpPacket* rtpPacket, char* frame,
                     uint32_t frameSize);

int handleCmd_OPTIONS(char* result, int cseq);

int handleCmd_DESCRIBE(char* result, int cseq, const char* url);

int handleCmd_SETUP(char* result, int cseq, int clientRtpPort);

int handleCmd_PLAY(char* result, int cseq);

void doClient(int clientSockfd, const char* clientIP, int clientPort);

// ---------- main ----------
int main() {
    int rtspServerSockfd = createTcpSocket();
    if (rtspServerSockfd < 0) return EXIT_FAILURE;

    if (bindSocketAddr(rtspServerSockfd, "127.0.0.1", SERVER_PORT) < 0 || listen(rtspServerSockfd, 10) < 0) {
        close(rtspServerSockfd);
        return EXIT_FAILURE;
    }

    std::printf("RTSP server started: rtsp://127.0.0.1:%d\n", SERVER_PORT);

    while (true) {
        char clientIp[64];
        int clientPort = 0;
        int clientSock = acceptClient(rtspServerSockfd, clientIp, &clientPort);
        if (clientSock < 0) {
            continue;
        }

        std::printf("Client connected %s:%d\n", clientIp, clientPort);
        doClient(clientSock, clientIp, clientPort);
    }
    close(rtspServerSockfd);
    return 0;
}
// ---------- Socket helpers ----------
int createTcpSocket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    int on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    return sockfd;
}

int createUdpSocket() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;

    int on = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    return sockfd;
}

int bindSocketAddr(int sockfd, const char* ip, int port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    return bind(sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
}

int acceptClient(int sockfd, char* ip, int* port) {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    int cfd = accept(sockfd, reinterpret_cast<sockaddr*>(&addr), &len);
    if (cfd < 0) return -1;

    std::strcpy(ip, inet_ntoa(addr.sin_addr));
    *port = ntohs(addr.sin_port);
    return cfd;
}

// ---------- H.264 parsing helpers ----------
bool startCode3(const char* buf) { return buf[0] == 0 && buf[1] == 0 && buf[2] == 1; }

bool startCode4(const char* buf) { return buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1; }

char* findNextStartCode(char* buf, int len) {
    if (len < 3) {
        return nullptr;
    }
    // 线性查找
    for (int i = 0; i < len - 3; ++i, ++buf) {
        if (startCode3(buf) || startCode4(buf)) {
            return buf;
        }
    }
    return nullptr;
}

int getFrameFromH264File(FILE* fp, char* frame, int size) {
    if (!fp) {
        return -1;
    }

    // 从 H264 文件中读取 size 大小的数据到 frame 中
    int rSize = fread(frame, 1, size, fp);

    // 检查 frame 是否以 NALU 开始码开头
    if (!startCode3(frame) && !startCode4(frame)) {
        return -1;
    }

    // 查找下一个 NALU 的开始码
    char* nextStartCode = findNextStartCode(frame + 3, rSize - 3);
    if (!nextStartCode) {
        return -1;
    }

    // 计算当前 NALU 的长度
    int frameSize = static_cast<int>(nextStartCode - frame);
    // 回退文件指针到正确位置
    fseek(fp, frameSize - rSize, SEEK_CUR);
    return frameSize;
}

// ---------- RTP send ----------
int rtpSendH264Frame(int serverRtpSockfd, const char* ip, int16_t port, RtpPacket* rtpPacket, char* frame,
                     uint32_t frameSize) {
    uint8_t firstByte = frame[0];  // 第一个字节 (8 位)
    int sendBytes = 0;             // 发送的字节数
    int ret = 0;                   // 返回值

    // 当一个 NALU 数据小于等于 RTP 最大包大小, 则直接发送
    if (frameSize <= RTP_MAX_PKT_SIZE) {
        //*   0 1 2 3 4 5 6 7 8 9
        //*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //*  |F|NRI|  Type   | a single NAL unit ... |
        //*  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        std::memcpy(rtpPacket->payload, frame, frameSize);
        ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, frameSize);
        if (ret < 0) {
            return -1;
        }
        // 更新 RTP 序列号
        rtpPacket->rtpHeader.seq++;
        sendBytes += ret;
        // 7: SPS 8: PPS
        uint8_t naluType = firstByte & 0x1F;   // NALU Type (后 5 位)
        if (naluType == 7 || naluType == 8) {  // 如果是SPS、PPS就不需要加时间戳
            return sendBytes;
        }
    }
    // 当一个 NALU 数据大于 RTP 最大包大小, 则需要分片发送 (FU-A 分片)
    else {
        //*  0                   1                   2
        //*  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
        //* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //* | FU indicator  |   FU header   |   FU payload   ...  |
        //* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        //*     FU Indicator
        //*    0 1 2 3 4 5 6 7
        //*   +-+-+-+-+-+-+-+-+
        //*   |F|NRI|  Type   |
        //*   +---------------+

        //*      FU Header
        //*    0 1 2 3 4 5 6 7
        //*   +-+-+-+-+-+-+-+-+
        //*   |S|E|R|  Type   |
        //*   +---------------+
        int pktNum = frameSize / RTP_MAX_PKT_SIZE;         // 分片数量
        int remainPktSize = frameSize % RTP_MAX_PKT_SIZE;  // 剩余数据大小
        int pos = 1;                                       // 跳过 NALU header 1 字节

        for (int i = 0; i < pktNum; ++i) {
            // FU Indicator
            // 0 | 1 2 | 3 4 5 6 7    （共8位）
            // F | NRI |   Type
            // NRI 同 NALU header 的 NRI, Type 为 28 (FU-A)
            rtpPacket->payload[0] = (firstByte & 0x60) | 28;  // 0x60: 0110 0000 保留 NALU header 的 NRI
            // FU Header
            // 0 | 1 | 2 | 3 4 5 6 7    （共8位）
            // S | E | R |   Type
            // S: 第一个分片
            // E: 最后一个分片
            // R: 保留位
            // Type: 同 NALU header 的 Type
            rtpPacket->payload[1] = firstByte & 0x1F;  // 0x1F: 0001 1111 保留 NALU header 的 Type

            // 第一个分片
            if (i == 0) {
                rtpPacket->payload[1] |= 0x80;  // 通过或上 1000 0000 置位 S
            }
            // 最后一个分片
            else if (remainPktSize == 0 && i == pktNum - 1) {
                rtpPacket->payload[1] |= 0x40;  // 通过或上 0100 0000 置位 E
            }
            // + pos 偏移
            std::memcpy(rtpPacket->payload + 2, frame + pos, RTP_MAX_PKT_SIZE);
            // 发送 RTP 包 (size + 2 是因为头部两个字节是 FU Indicator 和 FU Header)
            ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, RTP_MAX_PKT_SIZE + 2);
            if (ret < 0) {
                return -1;
            }
            // 更新 RTP 序列号
            rtpPacket->rtpHeader.seq++;
            sendBytes += ret;         // 更新发送的字节数
            pos += RTP_MAX_PKT_SIZE;  // 更新偏移
        }
        // 剩余数据大小大于 0, 则发送最后一个分片
        if (remainPktSize > 0) {
            rtpPacket->payload[0] = (firstByte & 0x60) | 28;    // FU Indicator
            rtpPacket->payload[1] = (firstByte & 0x1F) | 0x40;  // FU Header 置位 E

            std::memcpy(rtpPacket->payload + 2, frame + pos, remainPktSize);
            ret = rtpSendPacketOverUdp(serverRtpSockfd, ip, port, rtpPacket, remainPktSize + 2);
            if (ret < 0) {
                return -1;
            }
            // 更新 RTP 序列号
            rtpPacket->rtpHeader.seq++;
            sendBytes += ret;  // 更新发送的字节数
        }
    }
    // 更新 RTP 时间戳
    // 90000: 90kHz RTP 协议中 H.264 视频标准采样率
    // 25: 25fps 视频帧率
    // 90000 / 25 = 3600 表示 1 秒的 RTP 时间戳增量
    rtpPacket->rtpHeader.timestamp += 90000 / 25;
    return sendBytes;
}

// ---------- RTSP handlers (OPTIONS / DESCRIBE / SETUP / PLAY) ----------
int handleCmd_OPTIONS(char* result, int cseq) {
    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n",
                 cseq);
    return 0;
}

int handleCmd_DESCRIBE(char* result, int cseq, const char* url) {
    char sdp[512];
    char ip[64];
    std::sscanf(url, "rtsp://%63[^:]:", ip);

    std::sprintf(sdp,
                 "v=0\r\n"
                 "o=- %ld 1 IN IP4 %s\r\n"
                 "t=0 0\r\n"
                 "a=control:*\r\n"
                 "m=video 0 RTP/AVP 96\r\n"
                 "a=rtpmap:96 H264/90000\r\n"
                 "a=control:track0\r\n",
                 std::time(nullptr), ip);

    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Content-Base: %s\r\n"
                 "Content-Type: application/sdp\r\n"
                 "Content-Length: %zu\r\n\r\n"
                 "%s",
                 cseq, url, std::strlen(sdp), sdp);
    return 0;
}

int handleCmd_SETUP(char* result, int cseq, int clientRtpPort) {
    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Transport: RTP/AVP;unicast;"
                 "client_port=%d-%d;server_port=%d-%d\r\n"
                 "Session: 66334873\r\n\r\n",
                 cseq, clientRtpPort, clientRtpPort + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT);
    return 0;
}

int handleCmd_PLAY(char* result, int cseq) {
    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Range: npt=0.000-\r\n"
                 "Session: 66334873;timeout=10\r\n\r\n",
                 cseq);
    return 0;
}

// ---------- Per-client worker ----------
void doClient(int clientSockfd, const char* clientIP, int clientPort) {
    int serverRtpSockfd = -1;
    int serverRtcpSockfd = -1;

    auto* rBuf = static_cast<char*>(std::malloc(BUF_MAX_SIZE));
    auto* sBuf = static_cast<char*>(std::malloc(BUF_MAX_SIZE));

    char method[40]{};
    char url[128]{};
    int cseq = 0;
    int clientRtpPort = 0, clientRtcpPort = 0;
    bool playing = false;

    while (true) {
        int recvLen = recv(clientSockfd, rBuf, BUF_MAX_SIZE - 1, 0);
        if (recvLen <= 0) break;
        rBuf[recvLen] = '\0';

        // 解析 RTSP 报文
        const char* sep = "\n";
        // 按照每行解析
        for (char* line = std::strtok(rBuf, sep); line; line = std::strtok(nullptr, sep)) {
            if (std::strstr(line, "OPTIONS") || std::strstr(line, "DESCRIBE") || std::strstr(line, "SETUP") ||
                std::strstr(line, "PLAY")) {
                // 读取 method 和 url 并存储, 但 %*s 忽略 RTSP version
                std::sscanf(line, "%s %s %*s", method, url);
            } else if (std::strstr(line, "CSeq")) {
                // 读取 CSeq
                std::sscanf(line, "CSeq: %d", &cseq);
            } else if (!std::strncmp(line, "Transport:", 10)) {
                std::sscanf(line, "Transport: RTP/AVP%*[^;];unicast;client_port=%d-%d", &clientRtpPort,
                            &clientRtcpPort);
            }
        }

        // 处理 RTSP 请求
        if (!std::strcmp(method, "OPTIONS")) {
            handleCmd_OPTIONS(sBuf, cseq);
        } else if (!std::strcmp(method, "DESCRIBE")) {
            handleCmd_DESCRIBE(sBuf, cseq, url);
        } else if (!std::strcmp(method, "SETUP")) {
            handleCmd_SETUP(sBuf, cseq, clientRtpPort);

            serverRtpSockfd = createUdpSocket();
            serverRtcpSockfd = createUdpSocket();

            if (serverRtpSockfd < 0 || serverRtcpSockfd < 0) break;

            if (bindSocketAddr(serverRtpSockfd, "127.0.0.1", SERVER_RTP_PORT) < 0 ||
                bindSocketAddr(serverRtcpSockfd, "127.0.0.1", SERVER_RTCP_PORT) < 0) {
                break;
            }
        } else if (!std::strcmp(method, "PLAY")) {
            handleCmd_PLAY(sBuf, cseq);
            playing = true;
        } else {
            break;
        }

        send(clientSockfd, sBuf, std::strlen(sBuf), 0);

        // 如果是 PLAY 请求, 则开始发送 RTP 包
        if (playing) {
            FILE* fp = std::fopen(H264_FILE_NAME, "rb");
            if (!fp) break;

            auto* frame = static_cast<char*>(std::malloc(500000));
            auto* rtpPacket = static_cast<RtpPacket*>(std::malloc(500000));

            rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VESION, RTP_PAYLOAD_TYPE_H264, 0, 0, 0, 0x88923423);

            while (true) {
                // 从 H264 文件中获取一个 NALU
                int frameSize = getFrameFromH264File(fp, frame, 500000);
                if (frameSize < 0) {
                    break;
                }

                // 获取 NALU 的开始码
                int scSize = startCode3(frame) ? 3 : 4;
                // 发送 RTP 包
                // frame + scSize 表示 NALU 数据, frameSize - scSize 表示 NALU 数据长度
                rtpSendH264Frame(serverRtpSockfd, clientIP, clientRtpPort, rtpPacket, frame + scSize,
                                 frameSize - scSize);

                std::this_thread::sleep_for(std::chrono::milliseconds(40));
            }
            std::free(frame);
            std::free(rtpPacket);
            std::fclose(fp);
            break;
        }
    }

    close(clientSockfd);

    if (serverRtpSockfd >= 0) {
        close(serverRtpSockfd);
    }

    if (serverRtcpSockfd >= 0) {
        close(serverRtcpSockfd);
    }

    std::free(rBuf);
    std::free(sBuf);
}
