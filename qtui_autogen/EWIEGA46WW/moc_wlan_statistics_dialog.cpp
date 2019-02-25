/****************************************************************************
** Meta object code from reading C++ file 'wlan_statistics_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/wlan_statistics_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'wlan_statistics_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_WlanStatisticsDialog_t {
    QByteArrayData data[8];
    char stringdata0[110];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_WlanStatisticsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_WlanStatisticsDialog_t qt_meta_stringdata_WlanStatisticsDialog = {
    {
QT_MOC_LITERAL(0, 0, 20), // "WlanStatisticsDialog"
QT_MOC_LITERAL(1, 21, 8), // "fillTree"
QT_MOC_LITERAL(2, 30, 0), // ""
QT_MOC_LITERAL(3, 31, 19), // "addStationTreeItems"
QT_MOC_LITERAL(4, 51, 18), // "updateHeaderLabels"
QT_MOC_LITERAL(5, 70, 18), // "captureFileClosing"
QT_MOC_LITERAL(6, 89, 13), // "filterUpdated"
QT_MOC_LITERAL(7, 103, 6) // "filter"

    },
    "WlanStatisticsDialog\0fillTree\0\0"
    "addStationTreeItems\0updateHeaderLabels\0"
    "captureFileClosing\0filterUpdated\0"
    "filter"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_WlanStatisticsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   39,    2, 0x08 /* Private */,
       3,    0,   40,    2, 0x08 /* Private */,
       4,    0,   41,    2, 0x08 /* Private */,
       5,    0,   42,    2, 0x08 /* Private */,
       6,    1,   43,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    7,

       0        // eod
};

void WlanStatisticsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        WlanStatisticsDialog *_t = static_cast<WlanStatisticsDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->fillTree(); break;
        case 1: _t->addStationTreeItems(); break;
        case 2: _t->updateHeaderLabels(); break;
        case 3: _t->captureFileClosing(); break;
        case 4: _t->filterUpdated((*reinterpret_cast< QString(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject WlanStatisticsDialog::staticMetaObject = { {
    &TapParameterDialog::staticMetaObject,
    qt_meta_stringdata_WlanStatisticsDialog.data,
    qt_meta_data_WlanStatisticsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *WlanStatisticsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *WlanStatisticsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_WlanStatisticsDialog.stringdata0))
        return static_cast<void*>(this);
    return TapParameterDialog::qt_metacast(_clname);
}

int WlanStatisticsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = TapParameterDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 5)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 5;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 5)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 5;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
