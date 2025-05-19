#pragma once

#include <cstdint>

#define RTP_VESION 2
#define RTP_PAYLOAD_TYPE_H264 96  // H264 数据
#define RTP_PAYLOAD_TYPE_AAC 97   // AAC 数据
#define RTP_HEADER_SIZE 12        // RTP 头大小
#define RTP_MAX_PKT_SIZE 1400     // RTP 最大包大小 (防止切片)

/*
 *    0                   1                   2                   3
 *    7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           timestamp                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |           synchronization source (SSRC) identifier            |
 *   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *   |            contributing source (CSRC) identifiers             |
 *   :                             ....                              :
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct RtpHeader {
    /** byte 0 */
    uint8_t csrcLen : 4;    // CSRC 计数
    uint8_t extension : 1;  // 是否有扩展头
    uint8_t padding : 1;    // 是否有填充
    uint8_t version : 2;    // RTP 版本

    /** byte 1 */
    uint8_t payloadType : 7;  // 负载类型 (RTP 负载中数据的格式)
    uint8_t marker : 1;       // 标记位 (视频: 标记一帧的结束; 音频: 标记会话的开始)

    /** bytes 2–3 */
    uint16_t seq;  // 序列号

    /** bytes 4–7 */
    uint32_t timestamp;  // 时间戳

    /** bytes 8–11 */
    uint32_t ssrc;  // 同步源标识符 (唯一标识 RTP 流的源)

    // 这里省略了 CSRC (贡献源标识符列表)
};

struct RtpPacket {
    RtpHeader rtpHeader;
    // 通过 pkt->payload[i] 直接访问紧接在 rtpHeader 后分配的实际内存区域，缓存连续、无需二次跳转
    uint8_t payload[];  // NOTE: 柔性数组
};

void rtpHeaderInit(RtpPacket* rtpPacket, uint8_t csrcLen, uint8_t extension, uint8_t padding,
                   uint8_t version, uint8_t payloadType, uint8_t marker, uint16_t seq,
                   uint32_t timestamp, uint32_t ssrc);

int rtpSendPacketOverTcp(int clientSockfd, RtpPacket* rtpPacket, uint32_t dataSize);

int rtpSendPacketOverUdp(int serverRtpSockfd, const char* ip, int16_t port, RtpPacket* rtpPacket,
                         uint32_t dataSize);
