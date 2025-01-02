/****************************************************************************
** Meta object code from reading C++ file 'networkmonitor.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.15.16)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "networkmonitor.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'networkmonitor.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.15.16. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_NetworkMonitor_t {
    QByteArrayData data[11];
    char stringdata0[124];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_NetworkMonitor_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_NetworkMonitor_t qt_meta_stringdata_NetworkMonitor = {
    {
QT_MOC_LITERAL(0, 0, 14), // "NetworkMonitor"
QT_MOC_LITERAL(1, 15, 14), // "packetReceived"
QT_MOC_LITERAL(2, 30, 0), // ""
QT_MOC_LITERAL(3, 31, 13), // "updateDisplay"
QT_MOC_LITERAL(4, 45, 14), // "packetCallback"
QT_MOC_LITERAL(5, 60, 7), // "u_char*"
QT_MOC_LITERAL(6, 68, 8), // "userData"
QT_MOC_LITERAL(7, 77, 18), // "const pcap_pkthdr*"
QT_MOC_LITERAL(8, 96, 6), // "pkthdr"
QT_MOC_LITERAL(9, 103, 13), // "const u_char*"
QT_MOC_LITERAL(10, 117, 6) // "packet"

    },
    "NetworkMonitor\0packetReceived\0\0"
    "updateDisplay\0packetCallback\0u_char*\0"
    "userData\0const pcap_pkthdr*\0pkthdr\0"
    "const u_char*\0packet"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_NetworkMonitor[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   29,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    0,   30,    2, 0x08 /* Private */,
       4,    3,   31,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 5, 0x80000000 | 7, 0x80000000 | 9,    6,    8,   10,

       0        // eod
};

void NetworkMonitor::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<NetworkMonitor *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->packetReceived(); break;
        case 1: _t->updateDisplay(); break;
        case 2: _t->packetCallback((*reinterpret_cast< u_char*(*)>(_a[1])),(*reinterpret_cast< const pcap_pkthdr*(*)>(_a[2])),(*reinterpret_cast< const u_char*(*)>(_a[3]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (NetworkMonitor::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&NetworkMonitor::packetReceived)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject NetworkMonitor::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_NetworkMonitor.data,
    qt_meta_data_NetworkMonitor,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *NetworkMonitor::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *NetworkMonitor::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_NetworkMonitor.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int NetworkMonitor::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 3)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 3;
    }
    return _id;
}

// SIGNAL 0
void NetworkMonitor::packetReceived()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
