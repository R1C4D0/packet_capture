#pragma once

#ifndef PACKET_STRUCTURES_H
#define PACKET_STRUCTURES_H

#include <QString>
#include <QByteArray>
#include <pcap.h>

// Windows下需要的一些结构体定义
#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806

// TCP标志位定义
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// IP协议号定义
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

// 以太网帧头结构
struct ether_header {
    u_char ether_dhost[6];  // 目标MAC地址
    u_char ether_shost[6];  // 源MAC地址
    u_short ether_type;     // 协议类型
};

// IP头结构
struct ip_header {
    u_char  ip_vhl;                 // 版本 (4 bits) + 首部长度 (4 bits)
    u_char  ip_tos;                 // 服务类型
    u_short ip_len;                 // 总长度
    u_short ip_id;                  // 标识
    u_short ip_off;                 // 片偏移
    u_char  ip_ttl;                 // 生存时间
    u_char  ip_p;                   // 协议
    u_short ip_sum;                 // 校验和
    struct  in_addr ip_src;         // 源IP地址
    struct  in_addr ip_dst;         // 目标IP地址
};

// TCP头结构
struct tcp_header {
    u_short th_sport;               // 源端口
    u_short th_dport;               // 目标端口
    u_int   th_seq;                 // 序号
    u_int   th_ack;                 // 确认号
    u_char  th_offx2;              // 数据偏移和保留位
    u_char  th_flags;              // 标志位
    u_short th_win;                // 窗口大小
    u_short th_sum;                // 校验和
    u_short th_urp;                // 紧急指针
};

// UDP头结构
struct udp_header {
    u_short uh_sport;              // 源端口
    u_short uh_dport;              // 目标端口
    u_short uh_len;                // UDP长度
    u_short uh_sum;                // 校验和
};

// ICMP头结构
struct icmp_header {
    u_char type;                    // 类型
    u_char code;                    // 代码
    u_short checksum;              // 校验和
    u_short id;                    // 标识符
    u_short seq;                   // 序列号
};

// ARP头结构
struct arp_header {
    u_short ar_hrd;                // 硬件类型
    u_short ar_pro;                // 协议类型
    u_char  ar_hln;                // 硬件地址长度
    u_char  ar_pln;                // 协议地址长度
    u_short ar_op;                 // 操作码
    u_char  ar_sha[6];             // 发送方硬件地址
    u_char  ar_spa[4];             // 发送方协议地址
    u_char  ar_tha[6];             // 目标硬件地址
    u_char  ar_tpa[4];             // 目标协议地址
};

// 以太网信息结构
struct EthernetInfo {
    QString sourceMac;
    QString destMac;
    uint16_t etherType;
};

// IP信息结构
struct IPInfo {
    int version;
    int headerLength;
    int ttl;
    QString sourceIP;
    QString destIP;
};

// TCP信息结构
struct TCPInfo {
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t ackNumber;
    bool syn;
    bool ack;
    bool fin;
    bool rst;
    bool psh;
    bool urg;
    uint16_t window;
};

// UDP信息结构
struct UDPInfo {
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
};

// ICMP信息结构
struct ICMPInfo {
    uint8_t type;
    uint8_t code;
    QString typeDescription;
};

// ARP信息结构
struct ARPInfo {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint16_t operation;
    QString sourceMac;
    QString targetMac;
    QString sourceIP;
    QString targetIP;
};

// 数据包统计信息
struct PacketStats {
    int totalPackets;
    int tcpPackets;
    int udpPackets;
    int icmpPackets;
    int arpPackets;
    int otherPackets;
    int totalBytes;

    PacketStats() {
        totalPackets = 0;
        tcpPackets = 0;
        udpPackets = 0;
        icmpPackets = 0;
        arpPackets = 0;
        otherPackets = 0;
        totalBytes = 0;
    }
};

// 完整的数据包信息结构
struct PacketInfo {
    QByteArray rawData;
    qint64 timestamp;
    QString protocol;
    int length;

    EthernetInfo ethernet;
    IPInfo ip;
    TCPInfo tcp;
    UDPInfo udp;
    ICMPInfo icmp;
    ARPInfo arp;

    // 过滤用的字段
    bool marked;

    PacketInfo() : timestamp(0), length(0), marked(false) {
    }
};

// 过滤器结构
struct PacketFilter {
    QString protocol;
    QString srcMac;
    QString dstMac;
    QString srcIp;
    QString dstIp;
    int srcPort;
    int dstPort;

    PacketFilter() {
        srcPort = -1;
        dstPort = -1;
    }
};

#endif // PACKET_STRUCTURES_H
