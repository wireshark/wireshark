/****************************************************************************
** Meta object code from reading C++ file 'module_preferences_scroll_area.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/module_preferences_scroll_area.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'module_preferences_scroll_area.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ModulePreferencesScrollArea_t {
    QByteArrayData data[15];
    char stringdata0[310];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ModulePreferencesScrollArea_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ModulePreferencesScrollArea_t qt_meta_stringdata_ModulePreferencesScrollArea = {
    {
QT_MOC_LITERAL(0, 0, 27), // "ModulePreferencesScrollArea"
QT_MOC_LITERAL(1, 28, 22), // "uintLineEditTextEdited"
QT_MOC_LITERAL(2, 51, 0), // ""
QT_MOC_LITERAL(3, 52, 7), // "new_str"
QT_MOC_LITERAL(4, 60, 19), // "boolCheckBoxToggled"
QT_MOC_LITERAL(5, 80, 7), // "checked"
QT_MOC_LITERAL(6, 88, 22), // "enumRadioButtonToggled"
QT_MOC_LITERAL(7, 111, 31), // "enumComboBoxCurrentIndexChanged"
QT_MOC_LITERAL(8, 143, 5), // "index"
QT_MOC_LITERAL(9, 149, 24), // "stringLineEditTextEdited"
QT_MOC_LITERAL(10, 174, 29), // "rangeSyntaxLineEditTextEdited"
QT_MOC_LITERAL(11, 204, 20), // "uatPushButtonClicked"
QT_MOC_LITERAL(12, 225, 29), // "saveFilenamePushButtonClicked"
QT_MOC_LITERAL(13, 255, 29), // "openFilenamePushButtonClicked"
QT_MOC_LITERAL(14, 285, 24) // "dirnamePushButtonClicked"

    },
    "ModulePreferencesScrollArea\0"
    "uintLineEditTextEdited\0\0new_str\0"
    "boolCheckBoxToggled\0checked\0"
    "enumRadioButtonToggled\0"
    "enumComboBoxCurrentIndexChanged\0index\0"
    "stringLineEditTextEdited\0"
    "rangeSyntaxLineEditTextEdited\0"
    "uatPushButtonClicked\0saveFilenamePushButtonClicked\0"
    "openFilenamePushButtonClicked\0"
    "dirnamePushButtonClicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ModulePreferencesScrollArea[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   64,    2, 0x08 /* Private */,
       4,    1,   67,    2, 0x08 /* Private */,
       6,    1,   70,    2, 0x08 /* Private */,
       7,    1,   73,    2, 0x08 /* Private */,
       9,    1,   76,    2, 0x08 /* Private */,
      10,    1,   79,    2, 0x08 /* Private */,
      11,    0,   82,    2, 0x08 /* Private */,
      12,    0,   83,    2, 0x08 /* Private */,
      13,    0,   84,    2, 0x08 /* Private */,
      14,    0,   85,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::Bool,    5,
    QMetaType::Void, QMetaType::Bool,    5,
    QMetaType::Void, QMetaType::Int,    8,
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ModulePreferencesScrollArea::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ModulePreferencesScrollArea *_t = static_cast<ModulePreferencesScrollArea *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->uintLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->boolCheckBoxToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 2: _t->enumRadioButtonToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->enumComboBoxCurrentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->stringLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 5: _t->rangeSyntaxLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 6: _t->uatPushButtonClicked(); break;
        case 7: _t->saveFilenamePushButtonClicked(); break;
        case 8: _t->openFilenamePushButtonClicked(); break;
        case 9: _t->dirnamePushButtonClicked(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ModulePreferencesScrollArea::staticMetaObject = { {
    &QScrollArea::staticMetaObject,
    qt_meta_stringdata_ModulePreferencesScrollArea.data,
    qt_meta_data_ModulePreferencesScrollArea,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ModulePreferencesScrollArea::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ModulePreferencesScrollArea::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ModulePreferencesScrollArea.stringdata0))
        return static_cast<void*>(this);
    return QScrollArea::qt_metacast(_clname);
}

int ModulePreferencesScrollArea::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QScrollArea::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 10)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 10;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 10)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 10;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
