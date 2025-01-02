#include "networkmonitor.h"
#include <QHeaderView>
#include <QDateTime>
#include <QProcess>
#include <QRegularExpression>
#include <QFileDialog>
#include <QTextStream>
#include <QTimer>
#include <QMessageBox>
#include <stdexcept>

NetworkMonitor::NetworkMonitor(QWidget *parent)
    : QMainWindow(parent)
    , handle(nullptr)
    , showTcp(true)
    , showUdp(true)
    , settings(QApplication::organizationName(), QApplication::applicationName())
{
    setupUI();
    startCapture();
    connect(this, &NetworkMonitor::packetReceived, this, &NetworkMonitor::updateDisplay);
}

NetworkMonitor::~NetworkMonitor()
{
    saveSettings();
    if (handle) {
        pcap_close(handle);
    }
}

void NetworkMonitor::setupUI()
{
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    // Определяем, темная ли тема, по цвету фона
    bool isDarkTheme = qApp->palette().color(QPalette::Window).value() < 128;
    
    // Создаем все элементы интерфейса до применения стилей
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    QHBoxLayout *filterLayout = new QHBoxLayout();
    
    tcpCheckBox = new QCheckBox("TCP", this);
    udpCheckBox = new QCheckBox("UDP", this);
    tcpCheckBox->setChecked(true);
    udpCheckBox->setChecked(true);
    
    ipFilterEdit = new QLineEdit(this);
    ipFilterEdit->setPlaceholderText("Фильтр по IP");
    
    portFilterEdit = new QLineEdit(this);
    portFilterEdit->setPlaceholderText("Фильтр по портам");
    
    processFilterEdit = new QLineEdit(this);
    processFilterEdit->setPlaceholderText("Фильтр по процессу");
    
    trafficTable = new QTableWidget(this);
    trafficTable->setColumnCount(7);
    trafficTable->setHorizontalHeaderLabels({
        "Время", "Протокол", "Источник", "Назначение", 
        "Процесс", "Размер", "Порты"
    });
    trafficTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    
    // Теперь применяем стили
    if (isDarkTheme) {
        // Цвета для темной темы
        tcpColor = QColor(42, 86, 128);
        udpColor = QColor(128, 86, 42);
        
        QString tableStyle = 
            "QTableWidget { gridline-color: #353535; }"
            "QHeaderView::section { background-color: #353535; color: white; padding: 4px; border: none; }"
            "QTableWidget::item { padding: 4px; }";
            
        QString controlStyle = 
            "QCheckBox { color: white; }"
            "QCheckBox::indicator { width: 16px; height: 16px; }"
            "QCheckBox::indicator:unchecked { background-color: #252525; border: 1px solid #555; }"
            "QCheckBox::indicator:checked { background-color: #2A82DA; border: 1px solid #2A82DA; }"
            "QPushButton { background-color: #2A82DA; color: white; border: none; padding: 5px 15px; }"
            "QPushButton:hover { background-color: #3292EA; }"
            "QLineEdit { background-color: #252525; color: white; border: 1px solid #555; padding: 3px; }"
            "QLabel { color: white; }";
            
        trafficTable->setStyleSheet(tableStyle);
        centralWidget->setStyleSheet(controlStyle);
    } else {
        // Цвета для светлой темы
        tcpColor = QColor(225, 240, 255);
        udpColor = QColor(255, 240, 225);
        
        QString tableStyle = 
            "QTableWidget { gridline-color: #d0d0d0; }"
            "QHeaderView::section { background-color: #f0f0f0; color: black; padding: 4px; border: none; }"
            "QTableWidget::item { padding: 4px; }";
            
        QString controlStyle = 
            "QCheckBox { color: black; }"
            "QCheckBox::indicator { width: 16px; height: 16px; }"
            "QCheckBox::indicator:unchecked { background-color: white; border: 1px solid #aaa; }"
            "QCheckBox::indicator:checked { background-color: #0078d4; border: 1px solid #0078d4; }"
            "QPushButton { background-color: #0078d4; color: white; border: none; padding: 5px 15px; }"
            "QPushButton:hover { background-color: #1988d4; }"
            "QLineEdit { background-color: white; color: black; border: 1px solid #aaa; padding: 3px; }"
            "QLabel { color: black; }";
            
        trafficTable->setStyleSheet(tableStyle);
        centralWidget->setStyleSheet(controlStyle);
    }
    
    // Добавляем виджеты в layout
    filterLayout->addWidget(tcpCheckBox);
    filterLayout->addWidget(udpCheckBox);
    filterLayout->addWidget(new QLabel("IP:", this));
    filterLayout->addWidget(ipFilterEdit);
    filterLayout->addWidget(new QLabel("Порт:", this));
    filterLayout->addWidget(portFilterEdit);
    filterLayout->addWidget(new QLabel("Процесс:", this));
    filterLayout->addWidget(processFilterEdit);
    
    QPushButton *exportButton = new QPushButton("Экспорт в CSV", this);
    filterLayout->addWidget(exportButton);
    filterLayout->addStretch();
    
    mainLayout->addLayout(filterLayout);
    mainLayout->addWidget(trafficTable);
    
    // Подключаем сигналы
    connect(tcpCheckBox, &QCheckBox::checkStateChanged, this, &NetworkMonitor::updateFilters);
    connect(udpCheckBox, &QCheckBox::checkStateChanged, this, &NetworkMonitor::updateFilters);
    connect(ipFilterEdit, &QLineEdit::textChanged, this, &NetworkMonitor::updateIPFilter);
    connect(portFilterEdit, &QLineEdit::textChanged, this, &NetworkMonitor::updatePortFilter);
    connect(processFilterEdit, &QLineEdit::textChanged, this, &NetworkMonitor::updateProcessFilter);
    connect(exportButton, &QPushButton::clicked, this, &NetworkMonitor::exportToCSV);
    
    resize(1000, 600);
    
    setWindowTitle(QString("%1 %2")
        .arg(QApplication::applicationName())
        .arg(QApplication::applicationVersion()));
    
    loadSettings();
}

void NetworkMonitor::startCapture()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Находим сетевой интерфейс
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        qDebug() << "Error finding devices:" << errbuf;
        return;
    }

    // Выводим список найденных интерфейсов
    qDebug() << "Available interfaces:";
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        qDebug() << " -" << d->name << (d->description ? d->description : "");
    }
    
    // Открываем первый доступный интерфейс
    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == nullptr) {
        qDebug() << "Error opening device:" << errbuf;
        pcap_freealldevs(alldevs);
        return;
    }

    qDebug() << "Successfully opened interface:" << alldevs->name;
    pcap_freealldevs(alldevs);
    
    // Запускаем захват пакетов в отдельном потоке
    std::thread captureThread([this]() {
        qDebug() << "Starting packet capture thread";
        pcap_loop(handle, 0, packetCallback, reinterpret_cast<u_char*>(this));
        qDebug() << "Packet capture thread ended";
    });
    captureThread.detach();
}

void NetworkMonitor::packetCallback(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    NetworkMonitor *monitor = reinterpret_cast<NetworkMonitor*>(userData);
    monitor->processPacket(pkthdr, packet);
}

QString NetworkMonitor::getProcessName(const QString &srcIP, uint16_t srcPort)
{
    // Сначала пробуем через /proc/net/udp
    QFile udpFile("/proc/net/udp");
    if (udpFile.open(QIODevice::ReadOnly)) {
        QString udpData = udpFile.readAll();
        QStringList lines = udpData.split('\n');
        
        // Пропускаем заголовок
        lines.removeFirst();
        
        for (const QString &line : lines) {
            if (line.trimmed().isEmpty()) continue;
            
            QStringList parts = line.split(QRegularExpression("\\s+"));
            if (parts.size() >= 10) {
                // Парсим local_address
                QStringList local = parts[1].split(':');
                if (local.size() == 2) {
                    bool ok;
                    uint16_t port = local[1].toInt(&ok, 16);
                    if (ok && port == srcPort) {
                        // Получаем inode
                        QString inode = parts[9];
                        
                        // Ищем процесс по inode
                        QDir procDir("/proc");
                        QStringList procs = procDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::System);
                        
                        for (const QString &pid : procs) {
                            QDir fdDir(QString("/proc/%1/fd").arg(pid));
                            QStringList fds = fdDir.entryList(QDir::System);
                            
                            for (const QString &fd : fds) {
                                QString link = fdDir.canonicalPath() + "/" + fd;
                                QString target = QFile::symLinkTarget(link);
                                if (target.contains(inode)) {
                                    // Читаем имя процесса
                                    QFile commFile(QString("/proc/%1/comm").arg(pid));
                                    if (commFile.open(QIODevice::ReadOnly)) {
                                        return QString::fromUtf8(commFile.readAll()).trimmed();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Если не удалось определить через /proc/net/udp, пробуем через netstat
    QProcess netstat;
    netstat.start("netstat", QStringList() << "-np");
    netstat.waitForFinished();
    
    QString output = netstat.readAllStandardOutput();
    QStringList lines = output.split("\n");
    
    QString searchPattern = QString("%1:%2").arg(srcIP).arg(srcPort);
    
    for (const QString &line : lines) {
        if (line.contains(searchPattern)) {
            QStringList parts = line.split(QRegularExpression("\\s+"));
            if (parts.size() >= 7) {
                QString processInfo = parts[6];
                return processInfo.split("/").last();
            }
        }
    }
    
    return "Unknown";
}

void NetworkMonitor::processPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int packetCount = 0;
    qDebug() << "Received packet #" << ++packetCount;

    struct iphdr *ip = (struct iphdr*)(packet + 14);
    
    PacketInfo info;
    info.timestamp = QDateTime::currentDateTime().toString("hh:mm:ss.zzz");
    info.size = pkthdr->len;
    
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dstIP, INET_ADDRSTRLEN);
    
    info.srcIP = QString(srcIP);
    info.dstIP = QString(dstIP);
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr*)(packet + 14 + ip->ihl*4);
        info.protocol = "TCP";
        info.srcPort = ntohs(tcp->source);
        info.dstPort = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr*)(packet + 14 + ip->ihl*4);
        info.protocol = "UDP";
        info.srcPort = ntohs(udp->source);
        info.dstPort = ntohs(udp->dest);
    } else {
        info.protocol = QString::number(ip->protocol);
        info.srcPort = 0;
        info.dstPort = 0;
    }
    
    info.processName = getProcessName(info.srcIP, info.srcPort);
    
    {
        QMutexLocker locker(&mutex);
        packetQueue.append(info);
    }
    
    emit packetReceived();
}

bool NetworkMonitor::matchIPFilter(const QString &ip, const QString &filter)
{
    if (filter.isEmpty()) {
        return true;
    }
    return ip == filter;  // Точное совпадение для IP
}

bool NetworkMonitor::matchPortFilter(const QString &ports, const QString &filter)
{
    if (filter.isEmpty()) {
        return true;
    }
    
    QStringList portParts = ports.split(" → ");
    if (portParts.size() != 2) {
        return false;
    }
    
    bool ok;
    int filterPort = filter.toInt(&ok);
    if (!ok) {
        return false;
    }
    
    int srcPort = portParts[0].toInt(&ok);
    if (!ok) return false;
    
    int dstPort = portParts[1].toInt(&ok);
    if (!ok) return false;
    
    return srcPort == filterPort || dstPort == filterPort;
}

void NetworkMonitor::applyAllFilters()
{
    QMutexLocker locker(&mutex);
    
    QString ipFilter = ipFilterEdit->text();
    QString portFilter = portFilterEdit->text();
    QString processFilter = processFilterEdit->text();
    
    for (int row = 0; row < trafficTable->rowCount(); ++row) {
        QString protocol = trafficTable->item(row, 1)->text();
        QString srcIP = trafficTable->item(row, 2)->text();
        QString dstIP = trafficTable->item(row, 3)->text();
        QString process = trafficTable->item(row, 4)->text();
        QString ports = trafficTable->item(row, 6)->text();
        
        bool showByProtocol = (protocol == "TCP" && tcpCheckBox->isChecked()) ||
                             (protocol == "UDP" && udpCheckBox->isChecked());
                             
        bool showByIP = ipFilter.isEmpty() ||
                       matchIPFilter(srcIP, ipFilter) ||
                       matchIPFilter(dstIP, ipFilter);
                       
        bool showByPort = portFilter.isEmpty() ||
                         matchPortFilter(ports, portFilter);
                         
        bool showByProcess = processFilter.isEmpty() ||
                            process.contains(processFilter, Qt::CaseInsensitive);
        
        trafficTable->setRowHidden(row, 
            !(showByProtocol && showByIP && showByPort && showByProcess));
    }
}

// Обновляем все слоты фильтрации
void NetworkMonitor::updateIPFilter(const QString &)
{
    applyAllFilters();
}

void NetworkMonitor::updatePortFilter(const QString &)
{
    applyAllFilters();
}

void NetworkMonitor::updateProcessFilter(const QString &)
{
    applyAllFilters();
}

void NetworkMonitor::updateFilters()  // Для TCP/UDP чекбоксов
{
    applyAllFilters();
}

void NetworkMonitor::updateDisplay()
{
    QMutexLocker locker(&mutex);
    
    QScrollBar* scrollBar = trafficTable->verticalScrollBar();
    bool isAtBottom = scrollBar->value() == scrollBar->maximum();
    
    trafficTable->setUpdatesEnabled(false);
    
    for (PacketInfo info : packetQueue) {
        info.ports = QString("%1 → %2").arg(info.srcPort).arg(info.dstPort);
        
        bool showByProtocol = (info.protocol == "TCP" && tcpCheckBox->isChecked()) ||
                            (info.protocol == "UDP" && udpCheckBox->isChecked());
                            
        bool showByIP = ipFilterEdit->text().isEmpty() ||
                       matchIPFilter(info.srcIP, ipFilterEdit->text()) ||
                       matchIPFilter(info.dstIP, ipFilterEdit->text());
                       
        bool showByPort = portFilterEdit->text().isEmpty() ||
                         matchPortFilter(info.ports, portFilterEdit->text());
                         
        bool showByProcess = processFilterEdit->text().isEmpty() ||
                           info.processName.contains(processFilterEdit->text(), 
                                                   Qt::CaseInsensitive);
        
        int row = trafficTable->rowCount();
        trafficTable->insertRow(row);
        
        QTableWidgetItem *timeItem = new QTableWidgetItem(info.timestamp);
        QTableWidgetItem *protocolItem = new QTableWidgetItem(info.protocol);
        QTableWidgetItem *srcItem = new QTableWidgetItem(info.srcIP);
        QTableWidgetItem *dstItem = new QTableWidgetItem(info.dstIP);
        QTableWidgetItem *processItem = new QTableWidgetItem(info.processName);
        QTableWidgetItem *sizeItem = new QTableWidgetItem(QString::number(info.size));
        QTableWidgetItem *portsItem = new QTableWidgetItem(info.ports);
        
        trafficTable->setItem(row, 0, timeItem);
        trafficTable->setItem(row, 1, protocolItem);
        trafficTable->setItem(row, 2, srcItem);
        trafficTable->setItem(row, 3, dstItem);
        trafficTable->setItem(row, 4, processItem);
        trafficTable->setItem(row, 5, sizeItem);
        trafficTable->setItem(row, 6, portsItem);
        
        colorizePacket(row, info);
        
        trafficTable->setRowHidden(row, 
            !(showByProtocol && showByIP && showByPort && showByProcess));
    }
    
    packetQueue.clear();
    
    trafficTable->setUpdatesEnabled(true);
    
    if (isAtBottom) {
        QTimer::singleShot(0, this, [this]() {
            trafficTable->scrollToBottom();
            trafficTable->viewport()->update();
        });
    }
}

void NetworkMonitor::exportToCSV()
{
    QString fileName = QFileDialog::getSaveFileName(this, 
        "Сохранить как CSV", "", "CSV files (*.csv)");
    
    if (fileName.isEmpty()) return;
    
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::critical(this, "Ошибка",
            "Не удалось открыть файл для записи: " + file.errorString());
        return;
    }
    
    try {
        QTextStream stream(&file);
        stream.setEncoding(QStringConverter::Utf8);
        
        // Заголовки
        stream << "Время,Протокол,Источник,Назначение,Процесс,Размер,Порты\n";
        
        // Данные
        for (int row = 0; row < trafficTable->rowCount(); ++row) {
            if (!trafficTable->isRowHidden(row)) {
                QStringList rowData;
                for (int col = 0; col < trafficTable->columnCount(); ++col) {
                    rowData << trafficTable->item(row, col)->text();
                }
                stream << rowData.join(",") << "\n";
            }
        }
        
        if (stream.status() != QTextStream::Ok) {
            throw std::runtime_error("Ошибка записи в файл");
        }
        
    } catch (const std::exception &e) {
        QMessageBox::critical(this, "Ошибка",
            "Ошибка при экспорте данных: " + QString(e.what()));
    }
}

void NetworkMonitor::colorizePacket(int row, const PacketInfo &info)
{
    QColor color = info.protocol == "TCP" ? tcpColor : udpColor;
    
    for (int col = 0; col < trafficTable->columnCount(); ++col) {
        if (QTableWidgetItem *item = trafficTable->item(row, col)) {
            item->setBackground(color);
            // Цвет текста зависит от темы
            bool isDarkTheme = qApp->palette().color(QPalette::Window).value() < 128;
            item->setForeground(isDarkTheme ? Qt::white : Qt::black);
        }
    }
}

void NetworkMonitor::saveSettings()
{
    settings.setValue("tcp_enabled", tcpCheckBox->isChecked());
    settings.setValue("udp_enabled", udpCheckBox->isChecked());
    settings.setValue("ip_filter", ipFilterEdit->text());
    settings.setValue("port_filter", portFilterEdit->text());
    settings.setValue("process_filter", processFilterEdit->text());
}

void NetworkMonitor::loadSettings()
{
    tcpCheckBox->setChecked(settings.value("tcp_enabled", true).toBool());
    udpCheckBox->setChecked(settings.value("udp_enabled", true).toBool());
    ipFilterEdit->setText(settings.value("ip_filter", "").toString());
    portFilterEdit->setText(settings.value("port_filter", "").toString());
    processFilterEdit->setText(settings.value("process_filter", "").toString());
}