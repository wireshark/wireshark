/****************************************************************************
** Meta object code from reading C++ file 'rsa_keys_frame.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/rsa_keys_frame.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'rsa_keys_frame.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_RsaKeysFrame_t {
    QByteArrayData data[12];
    char stringdata0[216];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_RsaKeysFrame_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_RsaKeysFrame_t qt_meta_stringdata_RsaKeysFrame = {
    {
QT_MOC_LITERAL(0, 0, 12), // "RsaKeysFrame"
QT_MOC_LITERAL(1, 13, 17), // "keyCurrentChanged"
QT_MOC_LITERAL(2, 31, 0), // ""
QT_MOC_LITERAL(3, 32, 11), // "QModelIndex"
QT_MOC_LITERAL(4, 44, 7), // "current"
QT_MOC_LITERAL(5, 52, 8), // "previous"
QT_MOC_LITERAL(6, 61, 24), // "on_addFileButton_clicked"
QT_MOC_LITERAL(7, 86, 24), // "on_addItemButton_clicked"
QT_MOC_LITERAL(8, 111, 27), // "on_deleteItemButton_clicked"
QT_MOC_LITERAL(9, 139, 17), // "libCurrentChanged"
QT_MOC_LITERAL(10, 157, 27), // "on_addLibraryButton_clicked"
QT_MOC_LITERAL(11, 185, 30) // "on_deleteLibraryButton_clicked"

    },
    "RsaKeysFrame\0keyCurrentChanged\0\0"
    "QModelIndex\0current\0previous\0"
    "on_addFileButton_clicked\0"
    "on_addItemButton_clicked\0"
    "on_deleteItemButton_clicked\0"
    "libCurrentChanged\0on_addLibraryButton_clicked\0"
    "on_deleteLibraryButton_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_RsaKeysFrame[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    2,   49,    2, 0x08 /* Private */,
       6,    0,   54,    2, 0x08 /* Private */,
       7,    0,   55,    2, 0x08 /* Private */,
       8,    0,   56,    2, 0x08 /* Private */,
       9,    2,   57,    2, 0x08 /* Private */,
      10,    0,   62,    2, 0x08 /* Private */,
      11,    0,   63,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 3,    4,    5,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 3, 0x80000000 | 3,    4,    5,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void RsaKeysFrame::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        RsaKeysFrame *_t = static_cast<RsaKeysFrame *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->keyCurrentChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1])),(*reinterpret_cast< const QModelIndex(*)>(_a[2]))); break;
        case 1: _t->on_addFileButton_clicked(); break;
        case 2: _t->on_addItemButton_clicked(); break;
        case 3: _t->on_deleteItemButton_clicked(); break;
        case 4: _t->libCurrentChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1])),(*reinterpret_cast< const QModelIndex(*)>(_a[2]))); break;
        case 5: _t->on_addLibraryButton_clicked(); break;
        case 6: _t->on_deleteLibraryButton_clicked(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject RsaKeysFrame::staticMetaObject = { {
    &QFrame::staticMetaObject,
    qt_meta_stringdata_RsaKeysFrame.data,
    qt_meta_data_RsaKeysFrame,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *RsaKeysFrame::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RsaKeysFrame::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_RsaKeysFrame.stringdata0))
        return static_cast<void*>(this);
    return QFrame::qt_metacast(_clname);
}

int RsaKeysFrame::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QFrame::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
