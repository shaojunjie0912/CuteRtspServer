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
#include <iostream>
#include <string>
#include <thread>

#define AAC_FILE_NAME "/home/sjj/Workspace/CuteRtspServer/data/k-on.aac"
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

int parseAdtsHeader(uint8_t* in, struct AdtsHeader* res);

int rtpSendAACFrame(int socket, const char* ip, int16_t port, struct RtpPacket* rtpPacket, uint8_t* frame,
                    uint32_t frameSize);

int handleCmd_OPTIONS(char* result, int cseq);

int handleCmd_DESCRIBE(char* result, int cseq, const char* url);

int handleCmd_SETUP(char* result, int cseq, int clientRtpPort);

int handleCmd_PLAY(char* result, int cseq);

void doClient(int clientSockfd, const char* clientIP, int clientPort);

struct AdtsHeader {
    unsigned int syncword;      // 12 bit 同步字 '1111 1111 1111'，一个ADTS帧的开始
    uint8_t id;                 // 1 bit 0代表MPEG-4, 1代表MPEG-2。
    uint8_t layer;              // 2 bit 必须为0
    uint8_t protectionAbsent;   // 1 bit 1代表没有CRC，0代表有CRC
    uint8_t profile;            // 1 bit AAC级别（MPEG-2 AAC中定义了3种profile，MPEG-4 AAC中定义了6种profile）
    uint8_t samplingFreqIndex;  // 4 bit 采样率
    uint8_t privateBit;         // 1bit 编码时设置为0，解码时忽略
    uint8_t channelCfg;         // 3 bit 声道数量
    uint8_t originalCopy;       // 1bit 编码时设置为0，解码时忽略
    uint8_t home;               // 1 bit 编码时设置为0，解码时忽略

    uint8_t copyrightIdentificationBit;    // 1 bit 编码时设置为0，解码时忽略
    uint8_t copyrightIdentificationStart;  // 1 bit 编码时设置为0，解码时忽略
    unsigned int aacFrameLength;           // 13 bit 一个ADTS帧的长度包括ADTS头和AAC原始流
    unsigned int
        adtsBufferFullness;  // 11 bit
                             // 缓冲区充满度，0x7FF说明是码率可变的码流，不需要此字段。CBR可能需要此字段，不同编码器使用情况不同。这个在使用音频编码的时候需要注意。

    /* number_of_raw_data_blocks_in_frame
     * 表示ADTS帧中有number_of_raw_data_blocks_in_frame + 1个AAC原始帧
     * 所以说number_of_raw_data_blocks_in_frame == 0
     * 表示说ADTS帧中有一个AAC数据块并不是说没有。(一个AAC原始帧包含一段时间内1024个采样及相关数据)
     */
    uint8_t numberOfRawDataBlockInFrame;  // 2 bit
};

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

int parseAdtsHeader(uint8_t* in, struct AdtsHeader* res) {
    memset(res, 0, sizeof(*res));

    if ((in[0] == 0xFF) && ((in[1] & 0xF0) == 0xF0)) {
        res->id = ((uint8_t)in[1] & 0x08) >> 3;     // 第二个字节与0x08与运算之后，获得第13位bit对应的值
        res->layer = ((uint8_t)in[1] & 0x06) >> 1;  // 第二个字节与0x06与运算之后，右移1位，获得第14,15位两个bit对应的值
        res->protectionAbsent = (uint8_t)in[1] & 0x01;
        res->profile = ((uint8_t)in[2] & 0xc0) >> 6;
        res->samplingFreqIndex = ((uint8_t)in[2] & 0x3c) >> 2;
        res->privateBit = ((uint8_t)in[2] & 0x02) >> 1;
        res->channelCfg = ((((uint8_t)in[2] & 0x01) << 2) | (((unsigned int)in[3] & 0xc0) >> 6));
        res->originalCopy = ((uint8_t)in[3] & 0x20) >> 5;
        res->home = ((uint8_t)in[3] & 0x10) >> 4;
        res->copyrightIdentificationBit = ((uint8_t)in[3] & 0x08) >> 3;
        res->copyrightIdentificationStart = (uint8_t)in[3] & 0x04 >> 2;

        res->aacFrameLength = (((((unsigned int)in[3]) & 0x03) << 11) | (((unsigned int)in[4] & 0xFF) << 3) |
                               ((unsigned int)in[5] & 0xE0) >> 5);

        res->adtsBufferFullness = (((unsigned int)in[5] & 0x1f) << 6 | ((unsigned int)in[6] & 0xfc) >> 2);
        res->numberOfRawDataBlockInFrame = ((uint8_t)in[6] & 0x03);

        return 0;
    } else {
        printf("failed to parse adts header\n");
        return -1;
    }
}

int rtpSendAACFrame(int socket, const char* ip, int16_t port, struct RtpPacket* rtpPacket, uint8_t* frame,
                    uint32_t frameSize) {
    // 打包文档：https://blog.csdn.net/yangguoyu8023/article/details/106517251/

    // (针对 AAC) RTP 载荷的前 4 个字节
    rtpPacket->payload[0] = 0x00;                       // 标识负载类型为 AAC
    rtpPacket->payload[1] = 0x10;                       // 标识 AAC 的 profile 为 AAC-LC
    rtpPacket->payload[2] = (frameSize & 0x1FE0) >> 5;  // payload[2]: frameSize 的高 8 位
    rtpPacket->payload[3] = (frameSize & 0x1F) << 3;    // payload[3] 的高 5 位: frameSize 的低 5 位

    memcpy(rtpPacket->payload + 4, frame, frameSize);

    int ret = rtpSendPacketOverUdp(socket, ip, port, rtpPacket, frameSize + 4);
    if (ret < 0) {
        printf("failed to send rtp packet\n");
        return -1;
    }

    rtpPacket->rtpHeader.seq++;

    /*
     * 如果采样频率是44100
     * 一般AAC每个1024个采样为一帧
     * 所以一秒就有 44100 / 1024 = 43帧
     * 时间增量就是 44100 / 43 = 1025
     * 一帧的时间为 1 / 43 = 23ms
     */
    rtpPacket->rtpHeader.timestamp += 1025;

    return 0;
}

// ---------- RTSP handlers (OPTIONS / DESCRIBE / SETUP / PLAY) ----------
int handleCmd_OPTIONS(char* result, int cseq) {
    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Public: OPTIONS, DESCRIBE, SETUP, PLAY\r\n"
                 "\r\n",
                 cseq);
    return 0;
}

int handleCmd_DESCRIBE(char* result, int cseq, const char* url) {
    char sdp[512];
    char ip[64];
    std::sscanf(url, "rtsp://%63[^:]:", ip);

    std::sprintf(
        sdp,
        "v=0\r\n"
        "o=- 9%ld 1 IN IP4 %s\r\n"
        "t=0 0\r\n"
        "a=control:*\r\n"
        "m=audio 0 RTP/AVP 97\r\n"
        "a=rtpmap:97 mpeg4-generic/44100/2\r\n"
        "a=fmtp:97 profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config=1210;\r\n"
        "a=control:track0\r\n",
        std::time(nullptr), ip);

    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Content-Base: %s\r\n"
                 "Content-Type: application/sdp\r\n"
                 "Content-Length: %zu\r\n"
                 "\r\n"
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
                 "Session: 66334873\r\n"
                 "\r\n",
                 cseq, clientRtpPort, clientRtpPort + 1, SERVER_RTP_PORT, SERVER_RTCP_PORT);
    return 0;
}

int handleCmd_PLAY(char* result, int cseq) {
    std::sprintf(result,
                 "RTSP/1.0 200 OK\r\n"
                 "CSeq: %d\r\n"
                 "Range: npt=0.000-\r\n"
                 "Session: 66334873;timeout=10\r\n"
                 "\r\n",
                 cseq);
    return 0;
}

// ---------- Per-client worker ----------
void doClient(int clientSockfd, const char* clientIP, int clientPort) {
    int serverRtpSockfd = -1;
    int serverRtcpSockfd = -1;

    char* rBuf = static_cast<char*>(std::malloc(BUF_MAX_SIZE));
    char* sBuf = static_cast<char*>(std::malloc(BUF_MAX_SIZE));

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
                std::sscanf(line, "Transport: RTP/AVP/UDP;unicast;client_port=%d-%d", &clientRtpPort, &clientRtcpPort);
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

            if (serverRtpSockfd < 0 || serverRtcpSockfd < 0) {
                break;
            }

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

        // 发送 RTSP 响应
        send(clientSockfd, sBuf, std::strlen(sBuf), 0);

        // 如果是 PLAY 请求, 则开始发送 RTP 包
        if (playing) {
            AdtsHeader adtsHeader{};

            FILE* fp = std::fopen(AAC_FILE_NAME, "rb");
            if (!fp) {
                break;
            }

            uint8_t* frame = static_cast<uint8_t*>(std::malloc(5000));
            RtpPacket* rtpPacket = static_cast<RtpPacket*>(std::malloc(5000));

            rtpHeaderInit(rtpPacket, 0, 0, 0, RTP_VESION, RTP_PAYLOAD_TYPE_AAC, 1, 0, 0, 0x32411);

            while (true) {
                // 读取 ADTS Header
                int ret = std::fread(frame, 1, 7, fp);
                if (ret <= 0) {
                    std::cerr << "fread err\n";
                    break;
                }

                if (parseAdtsHeader(frame, &adtsHeader) < 0) {
                    std::cerr << "parseAdtsHeader err\n";
                    break;
                }

                if (std::fread(frame, 1, adtsHeader.aacFrameLength - 7, fp) <= 0) {
                    std::cerr << "fread err\n";
                    break;
                }

                rtpSendAACFrame(serverRtpSockfd, clientIP, clientRtpPort, rtpPacket, frame,
                                adtsHeader.aacFrameLength - 7);

                std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
