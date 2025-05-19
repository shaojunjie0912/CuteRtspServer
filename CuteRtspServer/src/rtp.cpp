#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <cutertspserver/rtp.hpp>

void rtpHeaderInit(RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension, uint8_t padding,
                   uint8_t version, uint8_t payloadType, uint8_t marker, uint16_t seq,
                   uint32_t timestamp, uint32_t ssrc) {
    rtpPacket->rtpHeader.csrcLen = csrcLen;
    rtpPacket->rtpHeader.extension = extension;
    rtpPacket->rtpHeader.padding = padding;
    rtpPacket->rtpHeader.version = version;
    rtpPacket->rtpHeader.payloadType = payloadType;
    rtpPacket->rtpHeader.marker = marker;
    rtpPacket->rtpHeader.seq = seq;
    rtpPacket->rtpHeader.timestamp = timestamp;
    rtpPacket->rtpHeader.ssrc = ssrc;
}

int rtpSendPacketOverTcp(int clientSockfd, RtpPacket* rtpPacket, uint32_t dataSize) {
    rtpPacket->rtpHeader.seq = htons(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = htonl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = htonl(rtpPacket->rtpHeader.ssrc);

    uint32_t rtpSize = RTP_HEADER_SIZE + dataSize;
    char* tempBuf = static_cast<char*>(malloc(4 + rtpSize));

    tempBuf[0] = 0x24;  // '$'
    tempBuf[1] = 0x00;
    tempBuf[2] = static_cast<uint8_t>((rtpSize & 0xFF00) >> 8);
    tempBuf[3] = static_cast<uint8_t>(rtpSize & 0xFF);
    std::memcpy(tempBuf + 4, rtpPacket, rtpSize);

    int ret = send(clientSockfd, tempBuf, 4 + rtpSize, 0);

    rtpPacket->rtpHeader.seq = ntohs(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = ntohl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = ntohl(rtpPacket->rtpHeader.ssrc);

    free(tempBuf);
    return ret;
}

int rtpSendPacketOverUdp(int serverRtpSockfd, const char* ip, int16_t port, RtpPacket* rtpPacket,
                         uint32_t dataSize) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    // 将多字节的字段转换为网络字节序
    rtpPacket->rtpHeader.seq = htons(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = htonl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = htonl(rtpPacket->rtpHeader.ssrc);

    int ret = sendto(serverRtpSockfd, rtpPacket, dataSize + RTP_HEADER_SIZE, 0,
                     reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    // 从网络字节序转换回主机字节序, 方便 seq 正确递增
    rtpPacket->rtpHeader.seq = ntohs(rtpPacket->rtpHeader.seq);
    rtpPacket->rtpHeader.timestamp = ntohl(rtpPacket->rtpHeader.timestamp);
    rtpPacket->rtpHeader.ssrc = ntohl(rtpPacket->rtpHeader.ssrc);

    return ret;
}
