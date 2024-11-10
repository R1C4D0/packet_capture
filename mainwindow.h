#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>
#include <QRadioButton>
#include <QLabel>
#include <QTableWidget>
#include <QComboBox>
#include "packetcapture.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void initSignalAndSlots();

private slots:
    void onCaptureStateChanged(bool start);
    void updatePacketInfo(const PacketInfo &packet);
    void clearPacketTable();
    void onPacketSelected(int row, int column);
    void onDeviceSelected(const QString &text);
    // 添加一个槽函数，用于处理错误信息
    void onErrorOccurred(const QString &error);

private:
    Ui::MainWindow *ui;
    // todo：最好一个PacketCapture对象监听一个设备，避免设备切换，若要同时监听多个设备，可以使用多个PacketCapture对象组成一个集合
    PacketCapture *captureThread;
    QRadioButton *captureButton;
    QLabel *statusLabel;//捕获状态显示
    QLabel *errorLabel;//错误信息显示
    QTableWidget *packetTable;
    QTableWidget *detailTable;
    void setupUI();
    void setupPacketTable();
    void setupDetailTable();
    void updateDetailTable(const PacketInfo &packet);
};

#endif // MAINWINDOW_H
