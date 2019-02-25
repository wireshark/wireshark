/****************************************************************************
** Meta object code from reading C++ file 'multicast_statistics_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/multicast_statistics_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'multicast_statistics_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_MulticastStatisticsDialog_t {
    QByteArrayData data[8];
    char stringdata0[104];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_MulticastStatisticsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_MulticastStatisticsDialog_t qt_meta_stringdata_MulticastStatisticsDialog = {
    {
QT_MOC_LITERAL(0, 0, 25), // "MulticastStatisticsDialog"
QT_MOC_LITERAL(1, 26, 13), // "updateWidgets"
QT_MOC_LITERAL(2, 40, 0), // ""
QT_MOC_LITERAL(3, 41, 25), // "updateMulticastParameters"
QT_MOC_LITERAL(4, 67, 8), // "fillTree"
QT_MOC_LITERAL(5, 76, 12), // "captureEvent"
QT_MOC_LITERAL(6, 89, 12), // "CaptureEvent"
QT_MOC_LITERAL(7, 102, 1) // "e"

    },
    "MulticastStatisticsDialog\0updateWidgets\0"
    "\0updateMulticastParameters\0fillTree\0"
    "captureEvent\0CaptureEvent\0e"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_MulticastStatisticsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   34,    2, 0x08 /* Private */,
       3,    0,   35,    2, 0x08 /* Private */,
       4,    0,   36,    2, 0x08 /* Private */,
       5,    1,   37,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 6,    7,

       0        // eod
};

void MulticastStatisticsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        MulticastStatisticsDialog *_t = static_cast<MulticastStatisticsDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->updateWidgets(); break;
        case 1: _t->updateMulticastParameters(); break;
        case 2: _t->fillTree(); break;
        case 3: _t->captureEvent((*reinterpret_cast< CaptureEvent(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject MulticastStatisticsDialog::staticMetaObject = { {
    &TapParameterDialog::staticMetaObject,
    qt_meta_stringdata_MulticastStatisticsDialog.data,
    qt_meta_data_MulticastStatisticsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *MulticastStatisticsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *MulticastStatisticsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_MulticastStatisticsDialog.stringdata0))
        return static_cast<void*>(this);
    return TapParameterDialog::qt_metacast(_clname);
}

int MulticastStatisticsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = TapParameterDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 4)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 4;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
