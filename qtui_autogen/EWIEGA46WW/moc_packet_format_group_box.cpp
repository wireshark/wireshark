/****************************************************************************
** Meta object code from reading C++ file 'packet_format_group_box.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/packet_format_group_box.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'packet_format_group_box.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_PacketFormatGroupBox_t {
    QByteArrayData data[11];
    char stringdata0[252];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_PacketFormatGroupBox_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_PacketFormatGroupBox_t qt_meta_stringdata_PacketFormatGroupBox = {
    {
QT_MOC_LITERAL(0, 0, 20), // "PacketFormatGroupBox"
QT_MOC_LITERAL(1, 21, 13), // "formatChanged"
QT_MOC_LITERAL(2, 35, 0), // ""
QT_MOC_LITERAL(3, 36, 26), // "on_summaryCheckBox_toggled"
QT_MOC_LITERAL(4, 63, 7), // "checked"
QT_MOC_LITERAL(5, 71, 26), // "on_detailsCheckBox_toggled"
QT_MOC_LITERAL(6, 98, 24), // "on_bytesCheckBox_toggled"
QT_MOC_LITERAL(7, 123, 40), // "on_includeColumnHeadingsCheck..."
QT_MOC_LITERAL(8, 164, 29), // "on_allCollapsedButton_toggled"
QT_MOC_LITERAL(9, 194, 28), // "on_asDisplayedButton_toggled"
QT_MOC_LITERAL(10, 223, 28) // "on_allExpandedButton_toggled"

    },
    "PacketFormatGroupBox\0formatChanged\0\0"
    "on_summaryCheckBox_toggled\0checked\0"
    "on_detailsCheckBox_toggled\0"
    "on_bytesCheckBox_toggled\0"
    "on_includeColumnHeadingsCheckBox_toggled\0"
    "on_allCollapsedButton_toggled\0"
    "on_asDisplayedButton_toggled\0"
    "on_allExpandedButton_toggled"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_PacketFormatGroupBox[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   54,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    1,   55,    2, 0x08 /* Private */,
       5,    1,   58,    2, 0x08 /* Private */,
       6,    1,   61,    2, 0x08 /* Private */,
       7,    1,   64,    2, 0x08 /* Private */,
       8,    1,   67,    2, 0x08 /* Private */,
       9,    1,   70,    2, 0x08 /* Private */,
      10,    1,   73,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,
    QMetaType::Void, QMetaType::Bool,    4,

       0        // eod
};

void PacketFormatGroupBox::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        PacketFormatGroupBox *_t = static_cast<PacketFormatGroupBox *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->formatChanged(); break;
        case 1: _t->on_summaryCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 2: _t->on_detailsCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->on_bytesCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->on_includeColumnHeadingsCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->on_allCollapsedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->on_asDisplayedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->on_allExpandedButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (PacketFormatGroupBox::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketFormatGroupBox::formatChanged)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject PacketFormatGroupBox::staticMetaObject = { {
    &QGroupBox::staticMetaObject,
    qt_meta_stringdata_PacketFormatGroupBox.data,
    qt_meta_data_PacketFormatGroupBox,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *PacketFormatGroupBox::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PacketFormatGroupBox::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_PacketFormatGroupBox.stringdata0))
        return static_cast<void*>(this);
    return QGroupBox::qt_metacast(_clname);
}

int PacketFormatGroupBox::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QGroupBox::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 8;
    }
    return _id;
}

// SIGNAL 0
void PacketFormatGroupBox::formatChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
