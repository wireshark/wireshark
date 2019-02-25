/****************************************************************************
** Meta object code from reading C++ file 'capture_file.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/capture_file.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_file.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_CaptureFile_t {
    QByteArrayData data[9];
    char stringdata0[113];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureFile_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureFile_t qt_meta_stringdata_CaptureFile = {
    {
QT_MOC_LITERAL(0, 0, 11), // "CaptureFile"
QT_MOC_LITERAL(1, 12, 12), // "captureEvent"
QT_MOC_LITERAL(2, 25, 0), // ""
QT_MOC_LITERAL(3, 26, 12), // "CaptureEvent"
QT_MOC_LITERAL(4, 39, 12), // "retapPackets"
QT_MOC_LITERAL(5, 52, 19), // "delayedRetapPackets"
QT_MOC_LITERAL(6, 72, 11), // "stopLoading"
QT_MOC_LITERAL(7, 84, 18), // "setCaptureStopFlag"
QT_MOC_LITERAL(8, 103, 9) // "stop_flag"

    },
    "CaptureFile\0captureEvent\0\0CaptureEvent\0"
    "retapPackets\0delayedRetapPackets\0"
    "stopLoading\0setCaptureStopFlag\0stop_flag"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureFile[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    0,   47,    2, 0x0a /* Public */,
       5,    0,   48,    2, 0x0a /* Public */,
       6,    0,   49,    2, 0x0a /* Public */,
       7,    1,   50,    2, 0x0a /* Public */,
       7,    0,   53,    2, 0x2a /* Public | MethodCloned */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    2,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void,

       0        // eod
};

void CaptureFile::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureFile *_t = static_cast<CaptureFile *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->captureEvent((*reinterpret_cast< CaptureEvent(*)>(_a[1]))); break;
        case 1: _t->retapPackets(); break;
        case 2: _t->delayedRetapPackets(); break;
        case 3: _t->stopLoading(); break;
        case 4: _t->setCaptureStopFlag((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->setCaptureStopFlag(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (CaptureFile::*)(CaptureEvent );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFile::captureEvent)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureFile::staticMetaObject = { {
    &QObject::staticMetaObject,
    qt_meta_stringdata_CaptureFile.data,
    qt_meta_data_CaptureFile,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureFile::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureFile::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureFile.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int CaptureFile::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void CaptureFile::captureEvent(CaptureEvent _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
