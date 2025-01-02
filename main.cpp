#include <QApplication>
#include "networkmonitor.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    
    // Устанавливаем информацию о приложении
    QApplication::setApplicationName("Network Monitor");
    QApplication::setApplicationVersion("1.0");
    QApplication::setOrganizationName("NetworkMonitor");
    
    NetworkMonitor w;
    w.show();
    
    return a.exec();
} 