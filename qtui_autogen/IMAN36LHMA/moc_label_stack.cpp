/****************************************************************************
** Meta object code from reading C++ file 'label_stack.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/label_stack.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'label_stack.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_LabelStack_t {
    QByteArrayData data[11];
    char stringdata0[123];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_LabelStack_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_LabelStack_t qt_meta_stringdata_LabelStack = {
    {
QT_MOC_LITERAL(0, 0, 10), // "LabelStack"
QT_MOC_LITERAL(1, 11, 20), // "toggleTemporaryFlash"
QT_MOC_LITERAL(2, 32, 0), // ""
QT_MOC_LITERAL(3, 33, 6), // "enable"
QT_MOC_LITERAL(4, 40, 14), // "mousePressedAt"
QT_MOC_LITERAL(5, 55, 10), // "global_pos"
QT_MOC_LITERAL(6, 66, 15), // "Qt::MouseButton"
QT_MOC_LITERAL(7, 82, 6), // "button"
QT_MOC_LITERAL(8, 89, 7), // "popText"
QT_MOC_LITERAL(9, 97, 3), // "ctx"
QT_MOC_LITERAL(10, 101, 21) // "updateTemporaryStatus"

    },
    "LabelStack\0toggleTemporaryFlash\0\0"
    "enable\0mousePressedAt\0global_pos\0"
    "Qt::MouseButton\0button\0popText\0ctx\0"
    "updateTemporaryStatus"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_LabelStack[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   34,    2, 0x06 /* Public */,
       4,    2,   37,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    1,   42,    2, 0x0a /* Public */,
      10,    0,   45,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool,    3,
    QMetaType::Void, QMetaType::QPoint, 0x80000000 | 6,    5,    7,

 // slots: parameters
    QMetaType::Void, QMetaType::Int,    9,
    QMetaType::Void,

       0        // eod
};

void LabelStack::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        LabelStack *_t = static_cast<LabelStack *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->toggleTemporaryFlash((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 1: _t->mousePressedAt((*reinterpret_cast< const QPoint(*)>(_a[1])),(*reinterpret_cast< Qt::MouseButton(*)>(_a[2]))); break;
        case 2: _t->popText((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->updateTemporaryStatus(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (LabelStack::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&LabelStack::toggleTemporaryFlash)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (LabelStack::*)(const QPoint & , Qt::MouseButton );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&LabelStack::mousePressedAt)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject LabelStack::staticMetaObject = { {
    &QLabel::staticMetaObject,
    qt_meta_stringdata_LabelStack.data,
    qt_meta_data_LabelStack,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *LabelStack::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *LabelStack::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_LabelStack.stringdata0))
        return static_cast<void*>(this);
    return QLabel::qt_metacast(_clname);
}

int LabelStack::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QLabel::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 4)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 4;
    }
    return _id;
}

// SIGNAL 0
void LabelStack::toggleTemporaryFlash(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void LabelStack::mousePressedAt(const QPoint & _t1, Qt::MouseButton _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
