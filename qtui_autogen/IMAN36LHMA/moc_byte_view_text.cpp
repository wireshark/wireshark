/****************************************************************************
** Meta object code from reading C++ file 'byte_view_text.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/byte_view_text.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'byte_view_text.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ByteViewText_t {
    QByteArrayData data[18];
    char stringdata0[196];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ByteViewText_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ByteViewText_t qt_meta_stringdata_ByteViewText = {
    {
QT_MOC_LITERAL(0, 0, 12), // "ByteViewText"
QT_MOC_LITERAL(1, 13, 11), // "byteHovered"
QT_MOC_LITERAL(2, 25, 0), // ""
QT_MOC_LITERAL(3, 26, 3), // "pos"
QT_MOC_LITERAL(4, 30, 12), // "byteSelected"
QT_MOC_LITERAL(5, 43, 16), // "setMonospaceFont"
QT_MOC_LITERAL(6, 60, 9), // "mono_font"
QT_MOC_LITERAL(7, 70, 12), // "markProtocol"
QT_MOC_LITERAL(8, 83, 5), // "start"
QT_MOC_LITERAL(9, 89, 6), // "length"
QT_MOC_LITERAL(10, 96, 9), // "markField"
QT_MOC_LITERAL(11, 106, 9), // "scroll_to"
QT_MOC_LITERAL(12, 116, 12), // "markAppendix"
QT_MOC_LITERAL(13, 129, 9), // "copyBytes"
QT_MOC_LITERAL(14, 139, 19), // "setHexDisplayFormat"
QT_MOC_LITERAL(15, 159, 8), // "QAction*"
QT_MOC_LITERAL(16, 168, 6), // "action"
QT_MOC_LITERAL(17, 175, 20) // "setCharacterEncoding"

    },
    "ByteViewText\0byteHovered\0\0pos\0"
    "byteSelected\0setMonospaceFont\0mono_font\0"
    "markProtocol\0start\0length\0markField\0"
    "scroll_to\0markAppendix\0copyBytes\0"
    "setHexDisplayFormat\0QAction*\0action\0"
    "setCharacterEncoding"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ByteViewText[] = {

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
       7,    2,   73,    2, 0x0a /* Public */,
      10,    3,   78,    2, 0x0a /* Public */,
      10,    2,   85,    2, 0x2a /* Public | MethodCloned */,
      12,    2,   90,    2, 0x0a /* Public */,
      13,    1,   95,    2, 0x08 /* Private */,
      14,    1,   98,    2, 0x08 /* Private */,
      17,    1,  101,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, QMetaType::Int,    3,

 // slots: parameters
    QMetaType::Void, QMetaType::QFont,    6,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    8,    9,
    QMetaType::Void, QMetaType::Int, QMetaType::Int, QMetaType::Bool,    8,    9,   11,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    8,    9,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    8,    9,
    QMetaType::Void, QMetaType::Bool,    2,
    QMetaType::Void, 0x80000000 | 15,   16,
    QMetaType::Void, 0x80000000 | 15,   16,

       0        // eod
};

void ByteViewText::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ByteViewText *_t = static_cast<ByteViewText *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->byteHovered((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->byteSelected((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->setMonospaceFont((*reinterpret_cast< const QFont(*)>(_a[1]))); break;
        case 3: _t->markProtocol((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 4: _t->markField((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3]))); break;
        case 5: _t->markField((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 6: _t->markAppendix((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 7: _t->copyBytes((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 8: _t->setHexDisplayFormat((*reinterpret_cast< QAction*(*)>(_a[1]))); break;
        case 9: _t->setCharacterEncoding((*reinterpret_cast< QAction*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 8:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAction* >(); break;
            }
            break;
        case 9:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAction* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ByteViewText::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ByteViewText::byteHovered)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ByteViewText::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ByteViewText::byteSelected)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ByteViewText::staticMetaObject = { {
    &QAbstractScrollArea::staticMetaObject,
    qt_meta_stringdata_ByteViewText.data,
    qt_meta_data_ByteViewText,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ByteViewText::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ByteViewText::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ByteViewText.stringdata0))
        return static_cast<void*>(this);
    if (!strcmp(_clname, "IDataPrintable"))
        return static_cast< IDataPrintable*>(this);
    if (!strcmp(_clname, "org.wireshark.Qt.UI.IDataPrintable"))
        return static_cast< IDataPrintable*>(this);
    return QAbstractScrollArea::qt_metacast(_clname);
}

int ByteViewText::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QAbstractScrollArea::qt_metacall(_c, _id, _a);
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
void ByteViewText::byteHovered(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ByteViewText::byteSelected(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
