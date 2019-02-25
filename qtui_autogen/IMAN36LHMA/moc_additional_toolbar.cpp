/****************************************************************************
** Meta object code from reading C++ file 'additional_toolbar.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/additional_toolbar.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'additional_toolbar.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_AdditionalToolbarWidgetAction_t {
    QByteArrayData data[8];
    char stringdata0[129];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_AdditionalToolbarWidgetAction_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_AdditionalToolbarWidgetAction_t qt_meta_stringdata_AdditionalToolbarWidgetAction = {
    {
QT_MOC_LITERAL(0, 0, 29), // "AdditionalToolbarWidgetAction"
QT_MOC_LITERAL(1, 30, 15), // "onButtonClicked"
QT_MOC_LITERAL(2, 46, 0), // ""
QT_MOC_LITERAL(3, 47, 17), // "onCheckBoxChecked"
QT_MOC_LITERAL(4, 65, 18), // "sendTextToCallback"
QT_MOC_LITERAL(5, 84, 26), // "onSelectionInWidgetChanged"
QT_MOC_LITERAL(6, 111, 3), // "idx"
QT_MOC_LITERAL(7, 115, 13) // "captureActive"

    },
    "AdditionalToolbarWidgetAction\0"
    "onButtonClicked\0\0onCheckBoxChecked\0"
    "sendTextToCallback\0onSelectionInWidgetChanged\0"
    "idx\0captureActive"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_AdditionalToolbarWidgetAction[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   39,    2, 0x08 /* Private */,
       3,    1,   40,    2, 0x08 /* Private */,
       4,    0,   43,    2, 0x08 /* Private */,
       5,    1,   44,    2, 0x08 /* Private */,
       7,    1,   47,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::Int,    2,

       0        // eod
};

void AdditionalToolbarWidgetAction::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        AdditionalToolbarWidgetAction *_t = static_cast<AdditionalToolbarWidgetAction *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->onButtonClicked(); break;
        case 1: _t->onCheckBoxChecked((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->sendTextToCallback(); break;
        case 3: _t->onSelectionInWidgetChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->captureActive((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject AdditionalToolbarWidgetAction::staticMetaObject = { {
    &QWidgetAction::staticMetaObject,
    qt_meta_stringdata_AdditionalToolbarWidgetAction.data,
    qt_meta_data_AdditionalToolbarWidgetAction,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *AdditionalToolbarWidgetAction::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AdditionalToolbarWidgetAction::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_AdditionalToolbarWidgetAction.stringdata0))
        return static_cast<void*>(this);
    return QWidgetAction::qt_metacast(_clname);
}

int AdditionalToolbarWidgetAction::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidgetAction::qt_metacall(_c, _id, _a);
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
struct qt_meta_stringdata_AdditionalToolBar_t {
    QByteArrayData data[1];
    char stringdata0[18];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_AdditionalToolBar_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_AdditionalToolBar_t qt_meta_stringdata_AdditionalToolBar = {
    {
QT_MOC_LITERAL(0, 0, 17) // "AdditionalToolBar"

    },
    "AdditionalToolBar"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_AdditionalToolBar[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       0,    0, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

       0        // eod
};

void AdditionalToolBar::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    Q_UNUSED(_o);
    Q_UNUSED(_id);
    Q_UNUSED(_c);
    Q_UNUSED(_a);
}

QT_INIT_METAOBJECT const QMetaObject AdditionalToolBar::staticMetaObject = { {
    &QToolBar::staticMetaObject,
    qt_meta_stringdata_AdditionalToolBar.data,
    qt_meta_data_AdditionalToolBar,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *AdditionalToolBar::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AdditionalToolBar::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_AdditionalToolBar.stringdata0))
        return static_cast<void*>(this);
    return QToolBar::qt_metacast(_clname);
}

int AdditionalToolBar::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QToolBar::qt_metacall(_c, _id, _a);
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
