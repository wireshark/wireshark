/****************************************************************************
** Meta object code from reading C++ file 'packet_range_group_box.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/packet_range_group_box.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'packet_range_group_box.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_PacketRangeGroupBox_t {
    QByteArrayData data[16];
    char stringdata0[307];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_PacketRangeGroupBox_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_PacketRangeGroupBox_t qt_meta_stringdata_PacketRangeGroupBox = {
    {
QT_MOC_LITERAL(0, 0, 19), // "PacketRangeGroupBox"
QT_MOC_LITERAL(1, 20, 15), // "validityChanged"
QT_MOC_LITERAL(2, 36, 0), // ""
QT_MOC_LITERAL(3, 37, 8), // "is_valid"
QT_MOC_LITERAL(4, 46, 12), // "rangeChanged"
QT_MOC_LITERAL(5, 59, 28), // "on_rangeLineEdit_textChanged"
QT_MOC_LITERAL(6, 88, 9), // "range_str"
QT_MOC_LITERAL(7, 98, 20), // "on_allButton_toggled"
QT_MOC_LITERAL(8, 119, 7), // "checked"
QT_MOC_LITERAL(9, 127, 25), // "on_selectedButton_toggled"
QT_MOC_LITERAL(10, 153, 23), // "on_markedButton_toggled"
QT_MOC_LITERAL(11, 177, 26), // "on_ftlMarkedButton_toggled"
QT_MOC_LITERAL(12, 204, 22), // "on_rangeButton_toggled"
QT_MOC_LITERAL(13, 227, 25), // "on_capturedButton_toggled"
QT_MOC_LITERAL(14, 253, 26), // "on_displayedButton_toggled"
QT_MOC_LITERAL(15, 280, 26) // "on_ignoredCheckBox_toggled"

    },
    "PacketRangeGroupBox\0validityChanged\0"
    "\0is_valid\0rangeChanged\0"
    "on_rangeLineEdit_textChanged\0range_str\0"
    "on_allButton_toggled\0checked\0"
    "on_selectedButton_toggled\0"
    "on_markedButton_toggled\0"
    "on_ftlMarkedButton_toggled\0"
    "on_rangeButton_toggled\0on_capturedButton_toggled\0"
    "on_displayedButton_toggled\0"
    "on_ignoredCheckBox_toggled"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_PacketRangeGroupBox[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x06 /* Public */,
       4,    0,   72,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   73,    2, 0x08 /* Private */,
       7,    1,   76,    2, 0x08 /* Private */,
       9,    1,   79,    2, 0x08 /* Private */,
      10,    1,   82,    2, 0x08 /* Private */,
      11,    1,   85,    2, 0x08 /* Private */,
      12,    1,   88,    2, 0x08 /* Private */,
      13,    1,   91,    2, 0x08 /* Private */,
      14,    1,   94,    2, 0x08 /* Private */,
      15,    1,   97,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    6,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,

       0        // eod
};

void PacketRangeGroupBox::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        PacketRangeGroupBox *_t = static_cast<PacketRangeGroupBox *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->validityChanged((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 1: _t->rangeChanged(); break;
        case 2: _t->on_rangeLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 3: _t->on_allButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->on_selectedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->on_markedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->on_ftlMarkedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->on_rangeButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 8: _t->on_capturedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 9: _t->on_displayedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 10: _t->on_ignoredCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (PacketRangeGroupBox::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketRangeGroupBox::validityChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (PacketRangeGroupBox::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketRangeGroupBox::rangeChanged)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject PacketRangeGroupBox::staticMetaObject = { {
    &QGroupBox::staticMetaObject,
    qt_meta_stringdata_PacketRangeGroupBox.data,
    qt_meta_data_PacketRangeGroupBox,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *PacketRangeGroupBox::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PacketRangeGroupBox::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_PacketRangeGroupBox.stringdata0))
        return static_cast<void*>(this);
    return QGroupBox::qt_metacast(_clname);
}

int PacketRangeGroupBox::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QGroupBox::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void PacketRangeGroupBox::validityChanged(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void PacketRangeGroupBox::rangeChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
