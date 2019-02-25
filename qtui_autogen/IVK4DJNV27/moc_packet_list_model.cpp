/****************************************************************************
** Meta object code from reading C++ file 'packet_list_model.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/models/packet_list_model.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'packet_list_model.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_PacketListModel_t {
    QByteArrayData data[29];
    char stringdata0[356];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_PacketListModel_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_PacketListModel_t qt_meta_stringdata_PacketListModel = {
    {
QT_MOC_LITERAL(0, 0, 15), // "PacketListModel"
QT_MOC_LITERAL(1, 16, 10), // "goToPacket"
QT_MOC_LITERAL(2, 27, 0), // ""
QT_MOC_LITERAL(3, 28, 19), // "maxLineCountChanged"
QT_MOC_LITERAL(4, 48, 11), // "QModelIndex"
QT_MOC_LITERAL(5, 60, 8), // "ih_index"
QT_MOC_LITERAL(6, 69, 17), // "itemHeightChanged"
QT_MOC_LITERAL(7, 87, 14), // "pushBusyStatus"
QT_MOC_LITERAL(8, 102, 6), // "status"
QT_MOC_LITERAL(9, 109, 13), // "popBusyStatus"
QT_MOC_LITERAL(10, 123, 18), // "pushProgressStatus"
QT_MOC_LITERAL(11, 142, 7), // "animate"
QT_MOC_LITERAL(12, 150, 17), // "terminate_is_stop"
QT_MOC_LITERAL(13, 168, 9), // "gboolean*"
QT_MOC_LITERAL(14, 178, 9), // "stop_flag"
QT_MOC_LITERAL(15, 188, 20), // "updateProgressStatus"
QT_MOC_LITERAL(16, 209, 5), // "value"
QT_MOC_LITERAL(17, 215, 17), // "popProgressStatus"
QT_MOC_LITERAL(18, 233, 22), // "bgColorizationProgress"
QT_MOC_LITERAL(19, 256, 5), // "first"
QT_MOC_LITERAL(20, 262, 4), // "last"
QT_MOC_LITERAL(21, 267, 4), // "sort"
QT_MOC_LITERAL(22, 272, 6), // "column"
QT_MOC_LITERAL(23, 279, 13), // "Qt::SortOrder"
QT_MOC_LITERAL(24, 293, 5), // "order"
QT_MOC_LITERAL(25, 299, 16), // "flushVisibleRows"
QT_MOC_LITERAL(26, 316, 11), // "dissectIdle"
QT_MOC_LITERAL(27, 328, 5), // "reset"
QT_MOC_LITERAL(28, 334, 21) // "emitItemHeightChanged"

    },
    "PacketListModel\0goToPacket\0\0"
    "maxLineCountChanged\0QModelIndex\0"
    "ih_index\0itemHeightChanged\0pushBusyStatus\0"
    "status\0popBusyStatus\0pushProgressStatus\0"
    "animate\0terminate_is_stop\0gboolean*\0"
    "stop_flag\0updateProgressStatus\0value\0"
    "popProgressStatus\0bgColorizationProgress\0"
    "first\0last\0sort\0column\0Qt::SortOrder\0"
    "order\0flushVisibleRows\0dissectIdle\0"
    "reset\0emitItemHeightChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_PacketListModel[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      15,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       9,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   89,    2, 0x06 /* Public */,
       3,    1,   92,    2, 0x06 /* Public */,
       6,    1,   95,    2, 0x06 /* Public */,
       7,    1,   98,    2, 0x06 /* Public */,
       9,    0,  101,    2, 0x06 /* Public */,
      10,    4,  102,    2, 0x06 /* Public */,
      15,    1,  111,    2, 0x06 /* Public */,
      17,    0,  114,    2, 0x06 /* Public */,
      18,    2,  115,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      21,    2,  120,    2, 0x0a /* Public */,
      21,    1,  125,    2, 0x2a /* Public | MethodCloned */,
      25,    0,  128,    2, 0x0a /* Public */,
      26,    1,  129,    2, 0x0a /* Public */,
      26,    0,  132,    2, 0x2a /* Public | MethodCloned */,
      28,    1,  133,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void, QMetaType::QString,    8,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool, QMetaType::Bool, 0x80000000 | 13,    8,   11,   12,   14,
    QMetaType::Void, QMetaType::Int,   16,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,   19,   20,

 // slots: parameters
    QMetaType::Void, QMetaType::Int, 0x80000000 | 23,   22,   24,
    QMetaType::Void, QMetaType::Int,   22,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   27,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 4,    5,

       0        // eod
};

void PacketListModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        PacketListModel *_t = static_cast<PacketListModel *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->goToPacket((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->maxLineCountChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        case 2: _t->itemHeightChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        case 3: _t->pushBusyStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 4: _t->popBusyStatus(); break;
        case 5: _t->pushProgressStatus((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3])),(*reinterpret_cast< gboolean*(*)>(_a[4]))); break;
        case 6: _t->updateProgressStatus((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->popProgressStatus(); break;
        case 8: _t->bgColorizationProgress((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 9: _t->sort((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< Qt::SortOrder(*)>(_a[2]))); break;
        case 10: _t->sort((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 11: _t->flushVisibleRows(); break;
        case 12: _t->dissectIdle((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 13: _t->dissectIdle(); break;
        case 14: _t->emitItemHeightChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (PacketListModel::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::goToPacket)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(const QModelIndex & ) const;
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::maxLineCountChanged)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(const QModelIndex & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::itemHeightChanged)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::pushBusyStatus)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::popBusyStatus)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(const QString & , bool , bool , gboolean * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::pushProgressStatus)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::updateProgressStatus)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::popProgressStatus)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (PacketListModel::*)(int , int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketListModel::bgColorizationProgress)) {
                *result = 8;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject PacketListModel::staticMetaObject = { {
    &QAbstractItemModel::staticMetaObject,
    qt_meta_stringdata_PacketListModel.data,
    qt_meta_data_PacketListModel,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *PacketListModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PacketListModel::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_PacketListModel.stringdata0))
        return static_cast<void*>(this);
    return QAbstractItemModel::qt_metacast(_clname);
}

int PacketListModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QAbstractItemModel::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 15)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 15;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 15)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 15;
    }
    return _id;
}

// SIGNAL 0
void PacketListModel::goToPacket(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void PacketListModel::maxLineCountChanged(const QModelIndex & _t1)const
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(const_cast< PacketListModel *>(this), &staticMetaObject, 1, _a);
}

// SIGNAL 2
void PacketListModel::itemHeightChanged(const QModelIndex & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void PacketListModel::pushBusyStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void PacketListModel::popBusyStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 4, nullptr);
}

// SIGNAL 5
void PacketListModel::pushProgressStatus(const QString & _t1, bool _t2, bool _t3, gboolean * _t4)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)), const_cast<void*>(reinterpret_cast<const void*>(&_t4)) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void PacketListModel::updateProgressStatus(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void PacketListModel::popProgressStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 7, nullptr);
}

// SIGNAL 8
void PacketListModel::bgColorizationProgress(int _t1, int _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
