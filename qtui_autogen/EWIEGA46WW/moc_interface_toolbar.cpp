/****************************************************************************
** Meta object code from reading C++ file 'interface_toolbar.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/interface_toolbar.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'interface_toolbar.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_InterfaceToolbar_t {
    QByteArrayData data[23];
    char stringdata0[337];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_InterfaceToolbar_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_InterfaceToolbar_t qt_meta_stringdata_InterfaceToolbar = {
    {
QT_MOC_LITERAL(0, 0, 16), // "InterfaceToolbar"
QT_MOC_LITERAL(1, 17, 11), // "closeReader"
QT_MOC_LITERAL(2, 29, 0), // ""
QT_MOC_LITERAL(3, 30, 20), // "interfaceListChanged"
QT_MOC_LITERAL(4, 51, 15), // "controlReceived"
QT_MOC_LITERAL(5, 67, 6), // "ifname"
QT_MOC_LITERAL(6, 74, 3), // "num"
QT_MOC_LITERAL(7, 78, 7), // "command"
QT_MOC_LITERAL(8, 86, 7), // "message"
QT_MOC_LITERAL(9, 94, 17), // "startReaderThread"
QT_MOC_LITERAL(10, 112, 10), // "control_in"
QT_MOC_LITERAL(11, 123, 13), // "updateWidgets"
QT_MOC_LITERAL(12, 137, 22), // "onControlButtonClicked"
QT_MOC_LITERAL(13, 160, 18), // "onLogButtonClicked"
QT_MOC_LITERAL(14, 179, 19), // "onHelpButtonClicked"
QT_MOC_LITERAL(15, 199, 22), // "onRestoreButtonClicked"
QT_MOC_LITERAL(16, 222, 17), // "onCheckBoxChanged"
QT_MOC_LITERAL(17, 240, 5), // "state"
QT_MOC_LITERAL(18, 246, 17), // "onComboBoxChanged"
QT_MOC_LITERAL(19, 264, 3), // "idx"
QT_MOC_LITERAL(20, 268, 17), // "onLineEditChanged"
QT_MOC_LITERAL(21, 286, 8), // "closeLog"
QT_MOC_LITERAL(22, 295, 41) // "on_interfacesComboBox_current..."

    },
    "InterfaceToolbar\0closeReader\0\0"
    "interfaceListChanged\0controlReceived\0"
    "ifname\0num\0command\0message\0startReaderThread\0"
    "control_in\0updateWidgets\0"
    "onControlButtonClicked\0onLogButtonClicked\0"
    "onHelpButtonClicked\0onRestoreButtonClicked\0"
    "onCheckBoxChanged\0state\0onComboBoxChanged\0"
    "idx\0onLineEditChanged\0closeLog\0"
    "on_interfacesComboBox_currentIndexChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_InterfaceToolbar[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      14,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   84,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    0,   85,    2, 0x0a /* Public */,
       4,    4,   86,    2, 0x0a /* Public */,
       9,    2,   95,    2, 0x08 /* Private */,
      11,    0,  100,    2, 0x08 /* Private */,
      12,    0,  101,    2, 0x08 /* Private */,
      13,    0,  102,    2, 0x08 /* Private */,
      14,    0,  103,    2, 0x08 /* Private */,
      15,    0,  104,    2, 0x08 /* Private */,
      16,    1,  105,    2, 0x08 /* Private */,
      18,    1,  108,    2, 0x08 /* Private */,
      20,    0,  111,    2, 0x08 /* Private */,
      21,    0,  112,    2, 0x08 /* Private */,
      22,    1,  113,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::Int, QMetaType::Int, QMetaType::QByteArray,    5,    6,    7,    8,
    QMetaType::Void, QMetaType::QString, QMetaType::VoidStar,    5,   10,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   17,
    QMetaType::Void, QMetaType::Int,   19,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    5,

       0        // eod
};

void InterfaceToolbar::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        InterfaceToolbar *_t = static_cast<InterfaceToolbar *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->closeReader(); break;
        case 1: _t->interfaceListChanged(); break;
        case 2: _t->controlReceived((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3])),(*reinterpret_cast< QByteArray(*)>(_a[4]))); break;
        case 3: _t->startReaderThread((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< void*(*)>(_a[2]))); break;
        case 4: _t->updateWidgets(); break;
        case 5: _t->onControlButtonClicked(); break;
        case 6: _t->onLogButtonClicked(); break;
        case 7: _t->onHelpButtonClicked(); break;
        case 8: _t->onRestoreButtonClicked(); break;
        case 9: _t->onCheckBoxChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->onComboBoxChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 11: _t->onLineEditChanged(); break;
        case 12: _t->closeLog(); break;
        case 13: _t->on_interfacesComboBox_currentIndexChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (InterfaceToolbar::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&InterfaceToolbar::closeReader)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject InterfaceToolbar::staticMetaObject = { {
    &QFrame::staticMetaObject,
    qt_meta_stringdata_InterfaceToolbar.data,
    qt_meta_data_InterfaceToolbar,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *InterfaceToolbar::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *InterfaceToolbar::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_InterfaceToolbar.stringdata0))
        return static_cast<void*>(this);
    return QFrame::qt_metacast(_clname);
}

int InterfaceToolbar::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QFrame::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 14)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 14;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 14)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 14;
    }
    return _id;
}

// SIGNAL 0
void InterfaceToolbar::closeReader()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
