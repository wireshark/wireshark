/****************************************************************************
** Meta object code from reading C++ file 'follow_stream_text.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/follow_stream_text.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'follow_stream_text.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_FollowStreamText_t {
    QByteArrayData data[4];
    char stringdata0[82];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_FollowStreamText_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_FollowStreamText_t qt_meta_stringdata_FollowStreamText = {
    {
QT_MOC_LITERAL(0, 0, 16), // "FollowStreamText"
QT_MOC_LITERAL(1, 17, 30), // "mouseMovedToTextCursorPosition"
QT_MOC_LITERAL(2, 48, 0), // ""
QT_MOC_LITERAL(3, 49, 32) // "mouseClickedOnTextCursorPosition"

    },
    "FollowStreamText\0mouseMovedToTextCursorPosition\0"
    "\0mouseClickedOnTextCursorPosition"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_FollowStreamText[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       2,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   24,    2, 0x06 /* Public */,
       3,    1,   27,    2, 0x06 /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void, QMetaType::Int,    2,

       0        // eod
};

void FollowStreamText::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        FollowStreamText *_t = static_cast<FollowStreamText *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->mouseMovedToTextCursorPosition((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->mouseClickedOnTextCursorPosition((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (FollowStreamText::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FollowStreamText::mouseMovedToTextCursorPosition)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (FollowStreamText::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FollowStreamText::mouseClickedOnTextCursorPosition)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject FollowStreamText::staticMetaObject = { {
    &QPlainTextEdit::staticMetaObject,
    qt_meta_stringdata_FollowStreamText.data,
    qt_meta_data_FollowStreamText,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *FollowStreamText::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FollowStreamText::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_FollowStreamText.stringdata0))
        return static_cast<void*>(this);
    return QPlainTextEdit::qt_metacast(_clname);
}

int FollowStreamText::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QPlainTextEdit::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 2)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 2)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 2;
    }
    return _id;
}

// SIGNAL 0
void FollowStreamText::mouseMovedToTextCursorPosition(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void FollowStreamText::mouseClickedOnTextCursorPosition(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
