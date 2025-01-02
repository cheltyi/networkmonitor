#ifndef NETWORKMONITOR_H
#define NETWORKMONITOR_H

#include <QMainWindow>
#include <QTimer>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QNetworkInformation>
#include <QNetworkInterface>
#include <QFile>
#include <QMutex>
#include <QDir>
#include <QProcess>
#include <QScrollBar>
#include <QRegularExpression>
#include <QLineEdit>
#include <QLabel>
#include <QHBoxLayout>
#include <QApplication>
#include <QStyleHints>
#include <QPalette>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <thread>
#include <QVector>
#include <QCheckBox>
#include <QPushButton>
#include <QFileDialog>
#include <QTextStream>
#include <QSettings>
#include <QMessageBox>
#include <stdexcept>

struct PacketInfo {
    QString timestamp;
    QString protocol;
    QString srcIP;
    QString dstIP;
    QString processName;
    QString ports;
    int size;
    uint16_t srcPort;
    uint16_t dstPort;
};

struct TrafficStats {
    qint64 totalBytes;
    int tcpPackets;
    int udpPackets;
    QMap<QString, qint64> bytesByProcess;
};

class NetworkMonitor : public QMainWindow
{
    Q_OBJECT

public:
    explicit NetworkMonitor(QWidget *parent = nullptr);
    ~NetworkMonitor();

signals:
    void packetReceived();

private slots:
    void updateDisplay();
    static void packetCallback(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    void updateFilters();
    void updateIPFilter(const QString &filter);
    void updatePortFilter(const QString &filter);
    void exportToCSV();
    void updateProcessFilter(const QString &filter);

private:
    QTableWidget *trafficTable;
    QCheckBox *tcpCheckBox;
    QCheckBox *udpCheckBox;
    pcap_t *handle;
    QVector<PacketInfo> packetQueue;
    QMutex mutex;
    bool showTcp;
    bool showUdp;
    QLineEdit *ipFilterEdit;
    QLineEdit *portFilterEdit;
    QLineEdit *processFilterEdit;
    TrafficStats stats;
    QLabel *statsLabel;
    QColor tcpColor;
    QColor udpColor;
    QSettings settings;
    
    void setupUI();
    void startCapture();
    QString getProcessName(const QString &srcIP, uint16_t srcPort);
    void processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet);
    bool matchIPFilter(const QString &ip, const QString &filter);
    bool matchPortFilter(const QString &ports, const QString &filter);
    void colorizePacket(int row, const PacketInfo &info);
    void applyAllFilters();
    void saveSettings();
    void loadSettings();
};

#endif 