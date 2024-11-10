#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "utils.h"
#include <QPushButton>
#include <QScrollBar>
#include <QSplitter>
#include <QVBoxLayout>
#include <QTableWidget>
#include <QHeaderView>



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , captureThread(new PacketCapture(this))
    , captureButton(new QRadioButton("开始捕获", this))
    , statusLabel(new QLabel("当前状态: 未捕获", this))
    , errorLabel(new QLabel(this))
    , packetTable(new QTableWidget(this))
    , detailTable(new QTableWidget(this))
{
    ui->setupUi(this);
    setupUI();
    // 连接信号和槽
    initSignalAndSlots();
}
MainWindow::~MainWindow()
{
    // 停止捕获线程，可以交给用captureThread的析构函数处理
    if (captureThread) {
        captureThread->stopCapture();  // 假设你有一个 stopCapture() 方法来停止捕获
        captureThread->wait();  // 等待捕获线程安全退出
        delete captureThread;
    }

    // 删除 UI 组件
    delete captureButton;
    delete statusLabel;
    delete packetTable;
    delete detailTable;

    // 删除 UI 的其他组件（由 ui 指针管理的）
    delete ui;
}

void MainWindow::onCaptureStateChanged(bool checked) {
    if (checked) {
        statusLabel->setText("当前状态: 正在捕获");
    } else {
        statusLabel->setText("当前状态: 已停止");
    }

    // 使用 QMetaObject::invokeMethod 确保在正确的线程上下文中调用
    QMetaObject::invokeMethod(captureThread, "onCaptureStateChanged",
                              Qt::QueuedConnection,
                              Q_ARG(bool, checked));
}


void MainWindow::setupUI()
{
    // 创建中央窗口部件
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    // 创建垂直布局
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);

    // 创建顶部控制面板
    QHBoxLayout *controlLayout = new QHBoxLayout();


    // 创建设备选择下拉框
    QComboBox *deviceComboBox = new QComboBox(this);
    deviceComboBox->addItems(captureThread->getDeviceList());

    // 创建清除按钮
    QPushButton *clearButton = new QPushButton("清除", this);

    // 添加控制组件到布局
    controlLayout->addWidget(captureButton);
    controlLayout->addWidget(statusLabel);
    controlLayout->addWidget(deviceComboBox);
    controlLayout->addWidget(clearButton);
    controlLayout->addStretch();

    // 创建分割布局
    QSplitter *splitter = new QSplitter(Qt::Vertical);

    // 设置数据包表格
    setupPacketTable();
    setupDetailTable();

    splitter->addWidget(packetTable);
    splitter->addWidget(detailTable);
    splitter->addWidget(errorLabel);

    // 添加所有组件到主布局
    mainLayout->addLayout(controlLayout);
    mainLayout->addWidget(splitter);
//    设置连接
    connect(clearButton, &QPushButton::clicked, this, &MainWindow::clearPacketTable);
    connect(deviceComboBox, &QComboBox::currentTextChanged, this, &MainWindow::onDeviceSelected);
    // 设置窗口属性
    setWindowTitle("网络包捕获分析器");
    resize(1200, 800);
}

void MainWindow::setupPacketTable()
{
    packetTable->setColumnCount(8);
    packetTable->setHorizontalHeaderLabels({
        "序号", "时间", "源MAC", "目标MAC", "源IP", "目标IP",
        "协议", "长度"
    });

    // 设置表格属性
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setSelectionMode(QAbstractItemView::SingleSelection);
//    将水平表头的列宽调整模式设置为交互式，这意味着用户可以手动调整列宽
    packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    packetTable->verticalHeader()->setVisible(false);
    packetTable->setShowGrid(true);
    packetTable->setAlternatingRowColors(true);
}

void MainWindow::setupDetailTable()
{
    detailTable->setColumnCount(2);
    detailTable->setHorizontalHeaderLabels({"字段", "值"});

    // 设置表格属性
    detailTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    detailTable->verticalHeader()->setVisible(false);
    detailTable->setShowGrid(true);
}

void MainWindow::updatePacketInfo(const PacketInfo &packet)
{
    // 添加异常处理
    try {
        // 更新UI的代码
        int row = packetTable->rowCount();
        packetTable->insertRow(row);

        // 设置基本信息
        packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(row + 1)));
        packetTable->setItem(row, 1, new QTableWidgetItem(formatTimestamp(packet.timestamp)));
        packetTable->setItem(row, 2, new QTableWidgetItem(packet.ethernet.sourceMac));
        packetTable->setItem(row, 3, new QTableWidgetItem(packet.ethernet.destMac));
        packetTable->setItem(row, 4, new QTableWidgetItem(packet.ip.sourceIP));
        packetTable->setItem(row, 5, new QTableWidgetItem(packet.ip.destIP));
        packetTable->setItem(row, 6, new QTableWidgetItem(packet.protocol));
        packetTable->setItem(row, 7, new QTableWidgetItem(QString::number(packet.length)));

        // 滚动到最新行
        packetTable->scrollToBottom();
    } catch (const std::exception &e) {
        qDebug() << "Error updating packet info:" << e.what();
    }
}

void MainWindow::updateDetailTable(const PacketInfo &packet)
{
    detailTable->setRowCount(0);

    auto addRow = [this](const QString &field, const QString &value) {
        int row = detailTable->rowCount();
        detailTable->insertRow(row);
        detailTable->setItem(row, 0, new QTableWidgetItem(field));
        detailTable->setItem(row, 1, new QTableWidgetItem(value));
    };

    // 添加以太网信息
    addRow("以太网帧", "");
    addRow("源MAC地址", packet.ethernet.sourceMac);
    addRow("目标MAC地址", packet.ethernet.destMac);
    addRow("类型", QString("0x%1").arg(packet.ethernet.etherType, 4, 16, QChar('0')));

    // 根据协议类型添加详细信息
    if (packet.protocol == "TCP") {
        addRow("IP信息", "");
        addRow("版本", QString::number(packet.ip.version));
        addRow("首部长度", QString::number(packet.ip.headerLength));
        addRow("TTL", QString::number(packet.ip.ttl));
        addRow("源IP", packet.ip.sourceIP);
        addRow("目标IP", packet.ip.destIP);

        addRow("TCP信息", "");
        addRow("源端口", QString::number(packet.tcp.sourcePort));
        addRow("目标端口", QString::number(packet.tcp.destPort));
        addRow("序号", QString::number(packet.tcp.sequenceNumber));
        addRow("确认号", QString::number(packet.tcp.ackNumber));
        addRow("标志", QString("SYN:%1 ACK:%2 FIN:%3 RST:%4 PSH:%5 URG:%6")
            .arg(packet.tcp.syn).arg(packet.tcp.ack)
            .arg(packet.tcp.fin).arg(packet.tcp.rst)
            .arg(packet.tcp.psh).arg(packet.tcp.urg));
    }
    else if (packet.protocol == "UDP") {
        addRow("UDP信息", "");
        addRow("源端口", QString::number(packet.udp.sourcePort));
        addRow("目标端口", QString::number(packet.udp.destPort));
        addRow("长度", QString::number(packet.udp.length));
    }
    else if (packet.protocol == "ICMP") {
        addRow("ICMP信息", "");
        addRow("类型", QString::number(packet.icmp.type));
        addRow("代码", QString::number(packet.icmp.code));
        addRow("描述", packet.icmp.typeDescription);
    }
    else if (packet.protocol == "ARP") {
        addRow("ARP信息", "");
        addRow("硬件类型", QString::number(packet.arp.hardwareType));
        addRow("协议类型", QString::number(packet.arp.protocolType));
        addRow("操作类型", packet.arp.operation == 1 ? "请求" : "响应");
        addRow("源MAC", packet.arp.sourceMac);
        addRow("源IP", packet.arp.sourceIP);
        addRow("目标MAC", packet.arp.targetMac);
        addRow("目标IP", packet.arp.targetIP);
    }
}


void MainWindow::clearPacketTable()
{
    packetTable->setRowCount(0);
    detailTable->setRowCount(0);
    //同时清除所保存的捕获Packet
    captureThread->clearPackets();
}

void MainWindow::onPacketSelected(int row, int column)
{
    Q_UNUSED(column);
    if (row >= 0 && row < packetTable->rowCount()) {
        // 获取所选中单元格的数据包信息并更新详细信息表
        // 这里需要修改 PacketCapture 类，添加获取指定包信息的方法
        const PacketInfo *packet = captureThread->getPacketInfo(row);
        // 调用 updateDetailTable 更新详细信息
        updateDetailTable(*packet);
    }
}

void MainWindow::onDeviceSelected(const QString &text)
{
    if (captureThread->Capturing()) {
        emit onErrorOccurred("正在捕获数据包，请先停止捕获");
        return;
    }
    QString deviceName = text.split(" (").first();
    captureThread->setDevice(deviceName);
}

void MainWindow::onErrorOccurred(const QString &error)
{
    // 显示错误信息
    errorLabel->setText(error);
}

void MainWindow::initSignalAndSlots()
{
    connect(captureButton, &QRadioButton::toggled, this, &MainWindow::onCaptureStateChanged);
    connect(packetTable, &QTableWidget::cellClicked, this, &MainWindow::onPacketSelected);
    connect(captureThread, &PacketCapture::errorOccurred, this, &MainWindow::onErrorOccurred);
    connect(captureThread, &PacketCapture::newPacketCaptured, this, &MainWindow::updatePacketInfo);
}
