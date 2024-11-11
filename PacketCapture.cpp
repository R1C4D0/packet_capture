#include "packetcapture.h"
#include <QThread>
#include <QDebug>
#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <QDebug>
#include <packet_structures.h>
#include <QMutexLocker>
#include <SignalEmitter.h>

PacketCapture::PacketCapture(QObject *parent) : QThread(parent), handle(nullptr), isCapturing(false) {
    // 初始化 Winsock 库（在 Windows 下需要初始化）
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        qWarning() << "Winsock initialization failed.";
    }
}

PacketCapture::~PacketCapture() {
    {
        QMutexLocker locker(&packetsMutex);
        if (isCapturing) {
            locker.unlock();  // 解锁以避免死锁
            stopCapture();    // stopCapture 内部会处理锁
            locker.relock();
        }
    }
    WSACleanup();  // 清理 Winsock
}

void PacketCapture::startCapture() {
    QMutexLocker locker(&packetsMutex);

    if (isCapturing) return;
    if (currentDevice.isEmpty()) {
//        emit errorOccurred("No device selected");
        SignalEmitter::getInstance().emitError("No device selected");
        return;
    }
    isCapturing = true;
    locker.unlock();//解锁后再启动线程
    start();
}

void PacketCapture::stopCapture()
{
    {
        QMutexLocker locker(&packetsMutex);
        if (!isCapturing) return;
        isCapturing = false;
    }
    {
        QMutexLocker handleLocker(&handleMutex);
//        pcap_loop 需要使用 pcap_breakloop 来中断
        if (handle) {
            pcap_breakloop(handle);  // 这会导致 pcap_loop 返回
            handleLocker.unlock();
            // 等待线程实际结束
            if (isRunning()) {
                if (!wait(2000)) {  // 等待最多2秒
                    terminate();//谨慎使用terminate
                    wait();
                }
            }

            handleLocker.relock();//重新加锁清理handle
            if (handle) {//再次检查handle是否有效
                pcap_close(handle);
                handle = nullptr;
            }
        }
    }
}

const PacketInfo *PacketCapture::getPacketInfo(int index)
{
    QMutexLocker locker(&packetsMutex);
    if (index >= 0 && index < capturedPackets.size()) {
        return &capturedPackets[index];
    }
    return nullptr;
}

void PacketCapture::clearPackets()
{
    QMutexLocker locker(&packetsMutex);
    capturedPackets.clear();
}

bool PacketCapture::Capturing()
{
    return isCapturing;
}


void PacketCapture::pcap_callback(u_char *user, const pcap_pkthdr *pkthdr, const u_char *packet)
{
    PacketCapture *pc = reinterpret_cast<PacketCapture *>(user);
//    复制数据包，避免在加锁期间访问共享数据
    QByteArray data(reinterpret_cast<const char *>(packet), pkthdr->len);
    {
        QMutexLocker locker(&pc->packetsMutex);
        if (!pc->isCapturing) return;
        pc->packetHandler(pkthdr, packet);//实际处理数据包的函数
    }
}

void PacketCapture::run()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    QString deviceCopy;
    {
        QMutexLocker locker(&packetsMutex);
        if (!Capturing()) return; //再次检查状态
        deviceCopy = currentDevice;  // 复制设备名，避免长时间持有锁
    }
    pcap_t* localHandle = pcap_open_live(
        deviceCopy.toUtf8().constData(),
        BUFSIZ, 1, 1000, errbuf
        );
    if (!localHandle) {
//        emit errorOccurred(QString("Couldn't open device %1: %2")
//                               .arg(deviceCopy)
//                               .arg(errbuf));
        SignalEmitter::getInstance().emitError(QString("Couldn't open device %1: %2")
                                                   .arg(deviceCopy)
                                                   .arg(errbuf));
        return;
    }
//    第一段加锁：将本地句柄赋值给共享变量handle
    {
//        QMutexLocker locker(&packetsMutex);
        QMutexLocker handlelocker(&handleMutex);
        if (!isCapturing) {  // 再次检查状态
            pcap_close(localHandle);
            return;
        }
        handle = localHandle;
    }

    /*
     *  pcap_loop 本身是 阻塞的，也就是说，它会在调用时停留在函数内部，直到满足某些条件才会返回。它的阻塞是针对当前线程的。
        尽管 pcap_loop 是阻塞的，但它的回调机制（通过 callback 函数）允许你在捕获数据包时做异步处理。
        也就是说，虽然 pcap_loop 在捕获数据包时会阻塞当前线程，但每捕获到一个数据包就会触发回调函数，这种方式提供了类似异步的行为。
     */
    pcap_loop(handle, 0, pcap_callback, reinterpret_cast<u_char *>(this));
//    第二段加锁：清理handle
    {
//        QMutexLocker locker(&packetsMutex);
        QMutexLocker handlelocker(&handleMutex);
        if (handle == localHandle) {
            pcap_close(handle);
            handle = nullptr;
        }
    }

}
/**
 * @brief PacketCapture::packetHandler作用：解析数据包并将解析结果封装到PacketInfo结构中并发射newPacketCaptured信号
 * @param header 数据包头部信息
 * @param packet 数据包内容
 */
void PacketCapture::packetHandler(const pcap_pkthdr *header, const u_char *packet) {
    PacketInfo packetInfo = parsePacket(packet, header->len);
//  将时间戳转换为毫秒
    packetInfo.timestamp = static_cast<qint64>(header->ts.tv_sec) * 1000LL +  static_cast<qint64>(header->ts.tv_usec) / 1000LL;
    packetInfo.length = header->len;

    // 解析以太网头
    const ether_header *ethHeader = reinterpret_cast<const ether_header*>(packet);

    // 设置MAC地址
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethHeader->ether_shost[0], ethHeader->ether_shost[1],
             ethHeader->ether_shost[2], ethHeader->ether_shost[3],
             ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
    packetInfo.ethernet.sourceMac = QString(macStr);

    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethHeader->ether_dhost[0], ethHeader->ether_dhost[1],
             ethHeader->ether_dhost[2], ethHeader->ether_dhost[3],
             ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]);
    packetInfo.ethernet.destMac = QString(macStr);

    // 获取以太网类型
    uint16_t etherType = ntohs(ethHeader->ether_type);

    if (etherType == ETHERTYPE_IP) {
        const ip_header* ipHeader = reinterpret_cast<const ip_header*>(packet + sizeof(ether_header));

        // 设置IP信息
        packetInfo.ip.version = (ipHeader->ip_vhl >> 4) & 0x0F;
        packetInfo.ip.headerLength = (ipHeader->ip_vhl & 0x0F) * 4;
        packetInfo.ip.ttl = ipHeader->ip_ttl;

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ipHeader->ip_src), ipStr, INET_ADDRSTRLEN);
        packetInfo.ip.sourceIP = QString(ipStr);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), ipStr, INET_ADDRSTRLEN);
        packetInfo.ip.destIP = QString(ipStr);

        const u_char* transportHeader = packet + sizeof(ether_header) + packetInfo.ip.headerLength;

        switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            const tcp_header* tcpHeader = reinterpret_cast<const tcp_header*>(transportHeader);
            packetInfo.tcp.sourcePort = ntohs(tcpHeader->th_sport);
            packetInfo.tcp.destPort = ntohs(tcpHeader->th_dport);
            packetInfo.tcp.sequenceNumber = ntohl(tcpHeader->th_seq);
            packetInfo.tcp.ackNumber = ntohl(tcpHeader->th_ack);
            packetInfo.tcp.syn = (tcpHeader->th_flags & TH_SYN) != 0;
            packetInfo.tcp.ack = (tcpHeader->th_flags & TH_ACK) != 0;
            packetInfo.tcp.fin = (tcpHeader->th_flags & TH_FIN) != 0;
            packetInfo.tcp.rst = (tcpHeader->th_flags & TH_RST) != 0;
            packetInfo.tcp.psh = (tcpHeader->th_flags & TH_PUSH) != 0;
            packetInfo.tcp.urg = (tcpHeader->th_flags & TH_URG) != 0;
            packetInfo.protocol = "TCP";
            break;
        }
        case IPPROTO_UDP: {
            const udp_header* udpHeader = reinterpret_cast<const udp_header*>(transportHeader);
            packetInfo.udp.sourcePort = ntohs(udpHeader->uh_sport);
            packetInfo.udp.destPort = ntohs(udpHeader->uh_dport);
            packetInfo.udp.length = ntohs(udpHeader->uh_len);
            packetInfo.protocol = "UDP";
            break;
        }
        case IPPROTO_ICMP: {
            const icmp_header* icmpHeader = reinterpret_cast<const icmp_header*>(transportHeader);
            packetInfo.icmp.type = icmpHeader->type;
            packetInfo.icmp.code = icmpHeader->code;
            packetInfo.protocol = "ICMP";

            switch (icmpHeader->type) {
            case 0:
                packetInfo.icmp.typeDescription = "Echo Reply";
                break;
            case 8:
                packetInfo.icmp.typeDescription = "Echo Request";
                break;
            default:
                packetInfo.icmp.typeDescription = "Other ICMP Type";
            }
            break;
        }
        }
    }
    else if (etherType == ETHERTYPE_ARP) {
        const arp_header* arpHeader = reinterpret_cast<const arp_header*>(packet + sizeof(ether_header));
        packetInfo.arp.hardwareType = ntohs(arpHeader->ar_hrd);
        packetInfo.arp.protocolType = ntohs(arpHeader->ar_pro);
        packetInfo.arp.operation = ntohs(arpHeader->ar_op);

        // 设置源MAC和目标MAC
        snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arpHeader->ar_sha[0], arpHeader->ar_sha[1],
                 arpHeader->ar_sha[2], arpHeader->ar_sha[3],
                 arpHeader->ar_sha[4], arpHeader->ar_sha[5]);
        packetInfo.arp.sourceMac = QString(macStr);

        // 设置源IP和目标IP
        struct in_addr addr;
        memcpy(&addr, arpHeader->ar_spa, 4);
        packetInfo.arp.sourceIP = QString(inet_ntoa(addr));
        memcpy(&addr, arpHeader->ar_tpa, 4);
        packetInfo.arp.targetIP = QString(inet_ntoa(addr));

        packetInfo.protocol = "ARP";
    }

    // 存储原始数据
    packetInfo.rawData = QByteArray(reinterpret_cast<const char*>(packet), header->len);

    {
//        QMutexLocker locker(&packetsMutex);
        capturedPackets.append(packetInfo);
    }

//    emit newPacketCaptured(packetInfo);
    SignalEmitter::getInstance().emitPacketCaptured(packetInfo);
}

void PacketCapture::onCaptureStateChanged(bool start)
{
    if (start) {
        if (!isRunning()){
            this->startCapture();
        }
    } else {
        this->stopCapture();
    }
}


void PacketCapture::setDevice(const QString &deviceName)
{
    QMutexLocker locker(&packetsMutex);
    if (isCapturing) {
//        emit errorOccurred("Cannot change device while capturing");
        SignalEmitter::getInstance().emitError("Cannot change device while capturing");
        return;
    }
    currentDevice = deviceName;
}
QString PacketCapture::getIpAddress(const u_char *data) {
    // 获取 IP 地址（源 IP）
    u_char *ipHeader = (u_char *)(data + 14);  // 假设是以太网头部后开始的 IP 数据包
    u_long srcIP = *((u_long *)(ipHeader + 12));  // 解析源IP
    struct in_addr srcAddr;
    srcAddr.s_addr = srcIP;
    return QString::fromStdString(inet_ntoa(srcAddr));  // 转换为 IP 字符串
}


// 实现获取设备列表的函数
QStringList PacketCapture::getDeviceList() {
    QStringList deviceList;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        SignalEmitter::getInstance().emitError(QString("Error finding devices: %1").arg(errbuf));
        return deviceList;
    }

    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        QString description = d->description ? d->description : "No description available";
        deviceList << QString("%1 (%2)").arg(d->name).arg(description);
    }

    pcap_freealldevs(alldevs);

    // 使用 SignalEmitter 发射设备列表更新信号
    SignalEmitter::getInstance().emitDeviceListUpdated(deviceList);
    return deviceList;
}
PacketInfo PacketCapture::parsePacket(const u_char *packet, int len)
{
    PacketInfo info;
    info.rawData = QByteArray(reinterpret_cast<const char*>(packet), len);

    // 解析以太网帧头
    struct ether_header *eth_header = (struct ether_header *)packet;
    info.ethernet.sourceMac = getMacAddress(eth_header->ether_shost);
    info.ethernet.destMac = getMacAddress(eth_header->ether_dhost);
    info.ethernet.etherType = ntohs(eth_header->ether_type);

    // 移动指针越过以太网帧头
    packet += sizeof(struct ether_header);

    // 根据协议类型解析上层协议
    switch (ntohs(eth_header->ether_type)) {
    case ETHERTYPE_IP: {
        struct ip_header *ip_header = (struct ip_header *)packet;
        info.ip.version = (ip_header->ip_vhl >> 4) & 0x0F;
        info.ip.headerLength = (ip_header->ip_vhl & 0x0F) * 4;
        info.ip.ttl = ip_header->ip_ttl;
        info.ip.sourceIP = QString(inet_ntoa(ip_header->ip_src));
        info.ip.destIP = QString(inet_ntoa(ip_header->ip_dst));

        packet += info.ip.headerLength;

        switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            info.protocol = "TCP";
            parseTcpPacket(packet, info);
            break;
        case IPPROTO_UDP:
            info.protocol = "UDP";
            parseUdpPacket(packet, info);
            break;
        case IPPROTO_ICMP:
            info.protocol = "ICMP";
            parseIcmpPacket(packet, info);
            break;
        default:
            info.protocol = "Unknown";
            break;
        }
        break;
    }
    case ETHERTYPE_ARP:
        info.protocol = "ARP";
        parseArpPacket(packet, info);
        break;
    default:
        info.protocol = "Unknown";
        break;
    }

    return info;
}

QString PacketCapture::getMacAddress(const u_char *addr)
{
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(addr[0], 2, 16, QChar('0'))
        .arg(addr[1], 2, 16, QChar('0'))
        .arg(addr[2], 2, 16, QChar('0'))
        .arg(addr[3], 2, 16, QChar('0'))
        .arg(addr[4], 2, 16, QChar('0'))
        .arg(addr[5], 2, 16, QChar('0'));
}

void PacketCapture::parseTcpPacket(const u_char *packet, PacketInfo &info)
{
    struct tcp_header *tcp = (struct tcp_header *)packet;
    info.tcp.sourcePort = ntohs(tcp->th_sport);
    info.tcp.destPort = ntohs(tcp->th_dport);
    info.tcp.sequenceNumber = ntohl(tcp->th_seq);
    info.tcp.ackNumber = ntohl(tcp->th_ack);
    info.tcp.syn = (tcp->th_flags & TH_SYN) != 0;
    info.tcp.ack = (tcp->th_flags & TH_ACK) != 0;
    info.tcp.fin = (tcp->th_flags & TH_FIN) != 0;
    info.tcp.rst = (tcp->th_flags & TH_RST) != 0;
    info.tcp.psh = (tcp->th_flags & TH_PUSH) != 0;
    info.tcp.urg = (tcp->th_flags & TH_URG) != 0;
    info.tcp.window = ntohs(tcp->th_win);
}

void PacketCapture::parseUdpPacket(const u_char *packet, PacketInfo &info)
{
    struct udp_header *udp = (struct udp_header *)packet;
    info.udp.sourcePort = ntohs(udp->uh_sport);
    info.udp.destPort = ntohs(udp->uh_dport);
    info.udp.length = ntohs(udp->uh_len);
    info.udp.checksum = ntohs(udp->uh_sum);
}

void PacketCapture::parseIcmpPacket(const u_char *packet, PacketInfo &info)
{
    struct icmp_header *icmp = (struct icmp_header *)packet;
    info.icmp.type = icmp->type;
    info.icmp.code = icmp->code;

    switch (icmp->type) {
    case 0:
        info.icmp.typeDescription = "Echo Reply";
        break;
    case 8:
        info.icmp.typeDescription = "Echo Request";
        break;
    case 3:
        info.icmp.typeDescription = "Destination Unreachable";
        break;
    case 5:
        info.icmp.typeDescription = "Redirect";
        break;
    default:
        info.icmp.typeDescription = "Other";
        break;
    }
}

void PacketCapture::parseArpPacket(const u_char *packet, PacketInfo &info)
{
    struct arp_header *arp = (struct arp_header *)packet;
    info.arp.hardwareType = ntohs(arp->ar_hrd);
    info.arp.protocolType = ntohs(arp->ar_pro);
    info.arp.operation = ntohs(arp->ar_op);
    info.arp.sourceMac = getMacAddress(arp->ar_sha);
    info.arp.targetMac = getMacAddress(arp->ar_tha);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->ar_spa, ip_str, INET_ADDRSTRLEN);
    info.arp.sourceIP = QString(ip_str);

    inet_ntop(AF_INET, arp->ar_tpa, ip_str, INET_ADDRSTRLEN);
    info.arp.targetIP = QString(ip_str);
}
