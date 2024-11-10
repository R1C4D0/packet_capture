#ifndef SIGNALEMITTER_H
#define SIGNALEMITTER_H

#pragma once

#include <QObject>
#include <QString>
#include "packet_structures.h"

class SignalEmitter : public QObject {
    Q_OBJECT

public:
    // 获取单例实例
    static SignalEmitter& getInstance() {
        static SignalEmitter instance;
        return instance;
    }

signals:
    void errorOccurred(const QString& message);  // 错误信号
    void packetCaptured(const PacketInfo& packetInfo);  // 数据包捕获信号
    void deviceListUpdated(const QStringList& deviceList);  // 设备列表更新信号

public:
    // 发射错误信号
    void emitError(const QString& message) {
        emit errorOccurred(message);
    }

    // 发射数据包捕获信号
    void emitPacketCaptured(const PacketInfo& packetInfo) {
        emit packetCaptured(packetInfo);
    }

    // 发射设备列表更新信号
    void emitDeviceListUpdated(const QStringList& deviceList) {
        emit deviceListUpdated(deviceList);
    }

private:
    // 私有化构造函数以实现单例模式
    SignalEmitter() {}
};


#endif // SIGNALEMITTER_H
