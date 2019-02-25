/****************************************************************************
** Meta object code from reading C++ file 'funnel_statistics.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/funnel_statistics.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'funnel_statistics.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_FunnelStatistics_t {
    QByteArrayData data[9];
    char stringdata0[132];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_FunnelStatistics_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_FunnelStatistics_t qt_meta_stringdata_FunnelStatistics = {
    {
QT_MOC_LITERAL(0, 0, 16), // "FunnelStatistics"
QT_MOC_LITERAL(1, 17, 16), // "setDisplayFilter"
QT_MOC_LITERAL(2, 34, 0), // ""
QT_MOC_LITERAL(3, 35, 6), // "filter"
QT_MOC_LITERAL(4, 42, 18), // "applyDisplayFilter"
QT_MOC_LITERAL(5, 61, 15), // "openCaptureFile"
QT_MOC_LITERAL(6, 77, 7), // "cf_path"
QT_MOC_LITERAL(7, 85, 21), // "funnelActionTriggered"
QT_MOC_LITERAL(8, 107, 24) // "displayFilterTextChanged"

    },
    "FunnelStatistics\0setDisplayFilter\0\0"
    "filter\0applyDisplayFilter\0openCaptureFile\0"
    "cf_path\0funnelActionTriggered\0"
    "displayFilterTextChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_FunnelStatistics[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   39,    2, 0x06 /* Public */,
       4,    0,   42,    2, 0x06 /* Public */,
       5,    2,   43,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       7,    0,   48,    2, 0x0a /* Public */,
       8,    1,   49,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    6,    3,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    3,

       0        // eod
};

void FunnelStatistics::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        FunnelStatistics *_t = static_cast<FunnelStatistics *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->setDisplayFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->applyDisplayFilter(); break;
        case 2: _t->openCaptureFile((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 3: _t->funnelActionTriggered(); break;
        case 4: _t->displayFilterTextChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (FunnelStatistics::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FunnelStatistics::setDisplayFilter)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (FunnelStatistics::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FunnelStatistics::applyDisplayFilter)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (FunnelStatistics::*)(QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FunnelStatistics::openCaptureFile)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject FunnelStatistics::staticMetaObject = { {
    &QObject::staticMetaObject,
    qt_meta_stringdata_FunnelStatistics.data,
    qt_meta_data_FunnelStatistics,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *FunnelStatistics::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FunnelStatistics::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_FunnelStatistics.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int FunnelStatistics::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void FunnelStatistics::setDisplayFilter(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void FunnelStatistics::applyDisplayFilter()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void FunnelStatistics::openCaptureFile(QString _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
