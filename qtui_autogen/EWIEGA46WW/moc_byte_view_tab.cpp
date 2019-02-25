/****************************************************************************
** Meta object code from reading C++ file 'byte_view_tab.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/byte_view_tab.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'byte_view_tab.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ByteViewTab_t {
    QByteArrayData data[15];
    char stringdata0[231];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ByteViewTab_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ByteViewTab_t qt_meta_stringdata_ByteViewTab = {
    {
QT_MOC_LITERAL(0, 0, 11), // "ByteViewTab"
QT_MOC_LITERAL(1, 12, 13), // "fieldSelected"
QT_MOC_LITERAL(2, 26, 0), // ""
QT_MOC_LITERAL(3, 27, 17), // "FieldInformation*"
QT_MOC_LITERAL(4, 45, 14), // "fieldHighlight"
QT_MOC_LITERAL(5, 60, 14), // "setCaptureFile"
QT_MOC_LITERAL(6, 75, 13), // "capture_file*"
QT_MOC_LITERAL(7, 89, 2), // "cf"
QT_MOC_LITERAL(8, 92, 20), // "selectedFrameChanged"
QT_MOC_LITERAL(9, 113, 20), // "selectedFieldChanged"
QT_MOC_LITERAL(10, 134, 23), // "highlightedFieldChanged"
QT_MOC_LITERAL(11, 158, 19), // "byteViewTextHovered"
QT_MOC_LITERAL(12, 178, 18), // "byteViewTextMarked"
QT_MOC_LITERAL(13, 197, 19), // "connectToMainWindow"
QT_MOC_LITERAL(14, 217, 13) // "captureActive"

    },
    "ByteViewTab\0fieldSelected\0\0FieldInformation*\0"
    "fieldHighlight\0setCaptureFile\0"
    "capture_file*\0cf\0selectedFrameChanged\0"
    "selectedFieldChanged\0highlightedFieldChanged\0"
    "byteViewTextHovered\0byteViewTextMarked\0"
    "connectToMainWindow\0captureActive"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ByteViewTab[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   64,    2, 0x06 /* Public */,
       4,    1,   67,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   70,    2, 0x0a /* Public */,
       8,    1,   73,    2, 0x0a /* Public */,
       9,    1,   76,    2, 0x0a /* Public */,
      10,    1,   79,    2, 0x0a /* Public */,
      11,    1,   82,    2, 0x08 /* Private */,
      12,    1,   85,    2, 0x08 /* Private */,
      13,    0,   88,    2, 0x08 /* Private */,
      14,    1,   89,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void, 0x80000000 | 3,    2,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void, 0x80000000 | 3,    2,
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    2,

       0        // eod
};

void ByteViewTab::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ByteViewTab *_t = static_cast<ByteViewTab *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->fieldSelected((*reinterpret_cast< FieldInformation*(*)>(_a[1]))); break;
        case 1: _t->fieldHighlight((*reinterpret_cast< FieldInformation*(*)>(_a[1]))); break;
        case 2: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 3: _t->selectedFrameChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->selectedFieldChanged((*reinterpret_cast< FieldInformation*(*)>(_a[1]))); break;
        case 5: _t->highlightedFieldChanged((*reinterpret_cast< FieldInformation*(*)>(_a[1]))); break;
        case 6: _t->byteViewTextHovered((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->byteViewTextMarked((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 8: _t->connectToMainWindow(); break;
        case 9: _t->captureActive((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 0:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< FieldInformation* >(); break;
            }
            break;
        case 1:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< FieldInformation* >(); break;
            }
            break;
        case 4:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< FieldInformation* >(); break;
            }
            break;
        case 5:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< FieldInformation* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ByteViewTab::*)(FieldInformation * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ByteViewTab::fieldSelected)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ByteViewTab::*)(FieldInformation * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ByteViewTab::fieldHighlight)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ByteViewTab::staticMetaObject = { {
    &QTabWidget::staticMetaObject,
    qt_meta_stringdata_ByteViewTab.data,
    qt_meta_data_ByteViewTab,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ByteViewTab::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ByteViewTab::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ByteViewTab.stringdata0))
        return static_cast<void*>(this);
    return QTabWidget::qt_metacast(_clname);
}

int ByteViewTab::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QTabWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    }
    return _id;
}

// SIGNAL 0
void ByteViewTab::fieldSelected(FieldInformation * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ByteViewTab::fieldHighlight(FieldInformation * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
