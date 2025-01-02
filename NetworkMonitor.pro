QT       += core gui network widgets

CONFIG += c++17

# Указываем правильные пути для Qt6
INCLUDEPATH += /usr/include/qt6
INCLUDEPATH += /usr/include/qt6/QtCore
INCLUDEPATH += /usr/include/qt6/QtGui
INCLUDEPATH += /usr/include/qt6/QtWidgets
INCLUDEPATH += /usr/include/qt6/QtNetwork

# Явно указываем путь к инструментам Qt6
QMAKE_MOC = /usr/lib/qt6/libexec/moc
QMAKE_UIC = /usr/lib/qt6/libexec/uic
QMAKE_RCC = /usr/lib/qt6/libexec/rcc

SOURCES += \
    main.cpp \
    networkmonitor.cpp

HEADERS += \
    networkmonitor.h

# Добавляем все необходимые библиотеки
LIBS += -lQt6Core -lQt6Gui -lQt6Widgets -lQt6Network -lpcap -lpthread

# Очистка перед сборкой
QMAKE_CLEAN += moc_*.cpp ui_*.h qrc_*.cpp

QMAKE_POST_LINK += sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET) 