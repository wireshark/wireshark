/****************************************************************************
** Meta object code from reading C++ file 'wireless_timeline.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/wireless_timeline.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'wireless_timeline.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_WirelessTimeline_t {
    QByteArrayData data[8];
    char stringdata0[97];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_WirelessTimeline_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_WirelessTimeline_t qt_meta_stringdata_WirelessTimeline = {
    {
QT_MOC_LITERAL(0, 0, 16), // "WirelessTimeline"
QT_MOC_LITERAL(1, 17, 22), // "bgColorizationProgress"
QT_MOC_LITERAL(2, 40, 0), // ""
QT_MOC_LITERAL(3, 41, 5), // "first"
QT_MOC_LITERAL(4, 47, 4), // "last"
QT_MOC_LITERAL(5, 52, 20), // "selectedFrameChanged"
QT_MOC_LITERAL(6, 73, 8), // "frameNum"
QT_MOC_LITERAL(7, 82, 14) // "appInitialized"

    },
    "WirelessTimeline\0bgColorizationProgress\0"
    "\0first\0last\0selectedFrameChanged\0"
    "frameNum\0appInitialized"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_WirelessTimeline[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    2,   29,    2, 0x0a /* Public */,
       5,    1,   34,    2, 0x0a /* Public */,
       7,    0,   37,    2, 0x0a /* Public */,

 // slots: parameters
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    3,    4,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void,

       0        // eod
};

void WirelessTimeline::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        WirelessTimeline *_t = static_cast<WirelessTimeline *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->bgColorizationProgress((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 1: _t->selectedFrameChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->appInitialized(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject WirelessTimeline::staticMetaObject = { {
    &QWidget::staticMetaObject,
    qt_meta_stringdata_WirelessTimeline.data,
    qt_meta_data_WirelessTimeline,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *WirelessTimeline::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *WirelessTimeline::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_WirelessTimeline.stringdata0))
        return static_cast<void*>(this);
    return QWidget::qt_metacast(_clname);
}

int WirelessTimeline::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
