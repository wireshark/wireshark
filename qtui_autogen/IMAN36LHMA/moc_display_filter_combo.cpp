/****************************************************************************
** Meta object code from reading C++ file 'display_filter_combo.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/display_filter_combo.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'display_filter_combo.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_DisplayFilterCombo_t {
    QByteArrayData data[7];
    char stringdata0[97];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_DisplayFilterCombo_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_DisplayFilterCombo_t qt_meta_stringdata_DisplayFilterCombo = {
    {
QT_MOC_LITERAL(0, 0, 18), // "DisplayFilterCombo"
QT_MOC_LITERAL(1, 19, 18), // "checkDisplayFilter"
QT_MOC_LITERAL(2, 38, 0), // ""
QT_MOC_LITERAL(3, 39, 18), // "applyDisplayFilter"
QT_MOC_LITERAL(4, 58, 16), // "setDisplayFilter"
QT_MOC_LITERAL(5, 75, 6), // "filter"
QT_MOC_LITERAL(6, 82, 14) // "updateMaxCount"

    },
    "DisplayFilterCombo\0checkDisplayFilter\0"
    "\0applyDisplayFilter\0setDisplayFilter\0"
    "filter\0updateMaxCount"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_DisplayFilterCombo[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   34,    2, 0x0a /* Public */,
       3,    0,   35,    2, 0x0a /* Public */,
       4,    1,   36,    2, 0x0a /* Public */,
       6,    0,   39,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Bool,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void,

       0        // eod
};

void DisplayFilterCombo::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        DisplayFilterCombo *_t = static_cast<DisplayFilterCombo *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: { bool _r = _t->checkDisplayFilter();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 1: _t->applyDisplayFilter(); break;
        case 2: _t->setDisplayFilter((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->updateMaxCount(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject DisplayFilterCombo::staticMetaObject = { {
    &QComboBox::staticMetaObject,
    qt_meta_stringdata_DisplayFilterCombo.data,
    qt_meta_data_DisplayFilterCombo,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *DisplayFilterCombo::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *DisplayFilterCombo::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_DisplayFilterCombo.stringdata0))
        return static_cast<void*>(this);
    return QComboBox::qt_metacast(_clname);
}

int DisplayFilterCombo::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QComboBox::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
