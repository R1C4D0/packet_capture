#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <pcap.h>
#include <QString>
#include <QThread>
#include <QMutex>
#include <QMap>
#include <packet_structures.h>

/**
 * @brief PacketCapture类继承了QThread类，可在单独的线程中进行网络数据包捕获。
 *  一个PacketCapture对象只能对应一个网络设备，每个线程独立使用自己的 pcap_t * 句柄，但可以在运行时切换设备
 *
 */
class PacketCapture : public QThread {
    Q_OBJECT

public:
    PacketCapture(QObject *parent = nullptr);
    ~PacketCapture();


    /**
     * @brief pcap_callback用于在pcap_loop中回调处理捕获到的数据包
     * @param user PacketCapture对象指针，可用于传递用户自定义数据或者上下文信息等
     * @param pkthdr 指向捕获到的数据包的头部信息
     * @param packet 指向捕获到的数据包的内容
     */
    static void pcap_callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    QStringList getDeviceList();
    void setDevice(const QString &deviceName);
    void startCapture();
    void stopCapture();
    const PacketInfo* getPacketInfo(int index);
    void clearPackets();
    bool Capturing();
protected:
    void run() override;

private:
    pcap_t *handle;
    QString currentDevice;
    volatile bool isCapturing;
    QVector<PacketInfo> capturedPackets;
    QMutex packetsMutex;
    QMutex handleMutex;

    static PacketInfo parsePacket(const u_char *packet, int len);
    static QString getMacAddress(const u_char *addr);
    static QString getIpAddress(const u_char *addr);
    static void parseTcpPacket(const u_char *packet, PacketInfo &info);
    static void parseUdpPacket(const u_char *packet, PacketInfo &info);
    static void parseIcmpPacket(const u_char *packet, PacketInfo &info);
    static void parseArpPacket(const u_char *packet, PacketInfo &info);

    void packetHandler(const pcap_pkthdr *, const u_char *);
signals:
    void newPacketCaptured(const PacketInfo &packet);
    void errorOccurred(const QString &error);
public slots:
    void onCaptureStateChanged(bool start);
};

#endif // PACKETCAPTURE_H
