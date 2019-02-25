/****************************************************************************
** Meta object code from reading C++ file 'resolved_addresses_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/resolved_addresses_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'resolved_addresses_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ResolvedAddressesDialog_t {
    QByteArrayData data[15];
    char stringdata0[370];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ResolvedAddressesDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ResolvedAddressesDialog_t qt_meta_stringdata_ResolvedAddressesDialog = {
    {
QT_MOC_LITERAL(0, 0, 23), // "ResolvedAddressesDialog"
QT_MOC_LITERAL(1, 24, 11), // "changeEvent"
QT_MOC_LITERAL(2, 36, 0), // ""
QT_MOC_LITERAL(3, 37, 7), // "QEvent*"
QT_MOC_LITERAL(4, 45, 5), // "event"
QT_MOC_LITERAL(5, 51, 33), // "on_actionAddressesHosts_trigg..."
QT_MOC_LITERAL(6, 85, 26), // "on_actionComment_triggered"
QT_MOC_LITERAL(7, 112, 32), // "on_actionIPv4HashTable_triggered"
QT_MOC_LITERAL(8, 145, 32), // "on_actionIPv6HashTable_triggered"
QT_MOC_LITERAL(9, 178, 28), // "on_actionPortNames_triggered"
QT_MOC_LITERAL(10, 207, 36), // "on_actionEthernetAddresses_tr..."
QT_MOC_LITERAL(11, 244, 40), // "on_actionEthernetManufacturer..."
QT_MOC_LITERAL(12, 285, 30), // "on_actionEthernetWKA_triggered"
QT_MOC_LITERAL(13, 316, 26), // "on_actionShowAll_triggered"
QT_MOC_LITERAL(14, 343, 26) // "on_actionHideAll_triggered"

    },
    "ResolvedAddressesDialog\0changeEvent\0"
    "\0QEvent*\0event\0on_actionAddressesHosts_triggered\0"
    "on_actionComment_triggered\0"
    "on_actionIPv4HashTable_triggered\0"
    "on_actionIPv6HashTable_triggered\0"
    "on_actionPortNames_triggered\0"
    "on_actionEthernetAddresses_triggered\0"
    "on_actionEthernetManufacturers_triggered\0"
    "on_actionEthernetWKA_triggered\0"
    "on_actionShowAll_triggered\0"
    "on_actionHideAll_triggered"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ResolvedAddressesDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x09 /* Protected */,
       5,    0,   72,    2, 0x08 /* Private */,
       6,    0,   73,    2, 0x08 /* Private */,
       7,    0,   74,    2, 0x08 /* Private */,
       8,    0,   75,    2, 0x08 /* Private */,
       9,    0,   76,    2, 0x08 /* Private */,
      10,    0,   77,    2, 0x08 /* Private */,
      11,    0,   78,    2, 0x08 /* Private */,
      12,    0,   79,    2, 0x08 /* Private */,
      13,    0,   80,    2, 0x08 /* Private */,
      14,    0,   81,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ResolvedAddressesDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ResolvedAddressesDialog *_t = static_cast<ResolvedAddressesDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->changeEvent((*reinterpret_cast< QEvent*(*)>(_a[1]))); break;
        case 1: _t->on_actionAddressesHosts_triggered(); break;
        case 2: _t->on_actionComment_triggered(); break;
        case 3: _t->on_actionIPv4HashTable_triggered(); break;
        case 4: _t->on_actionIPv6HashTable_triggered(); break;
        case 5: _t->on_actionPortNames_triggered(); break;
        case 6: _t->on_actionEthernetAddresses_triggered(); break;
        case 7: _t->on_actionEthernetManufacturers_triggered(); break;
        case 8: _t->on_actionEthernetWKA_triggered(); break;
        case 9: _t->on_actionShowAll_triggered(); break;
        case 10: _t->on_actionHideAll_triggered(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ResolvedAddressesDialog::staticMetaObject = { {
    &GeometryStateDialog::staticMetaObject,
    qt_meta_stringdata_ResolvedAddressesDialog.data,
    qt_meta_data_ResolvedAddressesDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ResolvedAddressesDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ResolvedAddressesDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ResolvedAddressesDialog.stringdata0))
        return static_cast<void*>(this);
    return GeometryStateDialog::qt_metacast(_clname);
}

int ResolvedAddressesDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = GeometryStateDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 11;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
