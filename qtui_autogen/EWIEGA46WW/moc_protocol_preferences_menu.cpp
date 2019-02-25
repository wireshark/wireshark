/****************************************************************************
** Meta object code from reading C++ file 'protocol_preferences_menu.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/protocol_preferences_menu.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'protocol_preferences_menu.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ProtocolPreferencesMenu_t {
    QByteArrayData data[15];
    char stringdata0[270];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ProtocolPreferencesMenu_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ProtocolPreferencesMenu_t qt_meta_stringdata_ProtocolPreferencesMenu = {
    {
QT_MOC_LITERAL(0, 0, 23), // "ProtocolPreferencesMenu"
QT_MOC_LITERAL(1, 24, 23), // "showProtocolPreferences"
QT_MOC_LITERAL(2, 48, 0), // ""
QT_MOC_LITERAL(3, 49, 11), // "module_name"
QT_MOC_LITERAL(4, 61, 22), // "editProtocolPreference"
QT_MOC_LITERAL(5, 84, 11), // "preference*"
QT_MOC_LITERAL(6, 96, 4), // "pref"
QT_MOC_LITERAL(7, 101, 12), // "pref_module*"
QT_MOC_LITERAL(8, 114, 6), // "module"
QT_MOC_LITERAL(9, 121, 24), // "disableProtocolTriggered"
QT_MOC_LITERAL(10, 146, 26), // "modulePreferencesTriggered"
QT_MOC_LITERAL(11, 173, 25), // "editorPreferenceTriggered"
QT_MOC_LITERAL(12, 199, 23), // "boolPreferenceTriggered"
QT_MOC_LITERAL(13, 223, 23), // "enumPreferenceTriggered"
QT_MOC_LITERAL(14, 247, 22) // "uatPreferenceTriggered"

    },
    "ProtocolPreferencesMenu\0showProtocolPreferences\0"
    "\0module_name\0editProtocolPreference\0"
    "preference*\0pref\0pref_module*\0module\0"
    "disableProtocolTriggered\0"
    "modulePreferencesTriggered\0"
    "editorPreferenceTriggered\0"
    "boolPreferenceTriggered\0enumPreferenceTriggered\0"
    "uatPreferenceTriggered"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ProtocolPreferencesMenu[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   54,    2, 0x06 /* Public */,
       4,    2,   57,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    0,   62,    2, 0x08 /* Private */,
      10,    0,   63,    2, 0x08 /* Private */,
      11,    0,   64,    2, 0x08 /* Private */,
      12,    0,   65,    2, 0x08 /* Private */,
      13,    0,   66,    2, 0x08 /* Private */,
      14,    0,   67,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, 0x80000000 | 5, 0x80000000 | 7,    6,    8,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ProtocolPreferencesMenu::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ProtocolPreferencesMenu *_t = static_cast<ProtocolPreferencesMenu *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->showProtocolPreferences((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->editProtocolPreference((*reinterpret_cast< preference*(*)>(_a[1])),(*reinterpret_cast< pref_module*(*)>(_a[2]))); break;
        case 2: _t->disableProtocolTriggered(); break;
        case 3: _t->modulePreferencesTriggered(); break;
        case 4: _t->editorPreferenceTriggered(); break;
        case 5: _t->boolPreferenceTriggered(); break;
        case 6: _t->enumPreferenceTriggered(); break;
        case 7: _t->uatPreferenceTriggered(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolPreferencesMenu::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProtocolPreferencesMenu::showProtocolPreferences)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (ProtocolPreferencesMenu::*)(preference * , pref_module * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProtocolPreferencesMenu::editProtocolPreference)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ProtocolPreferencesMenu::staticMetaObject = { {
    &QMenu::staticMetaObject,
    qt_meta_stringdata_ProtocolPreferencesMenu.data,
    qt_meta_data_ProtocolPreferencesMenu,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ProtocolPreferencesMenu::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolPreferencesMenu::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ProtocolPreferencesMenu.stringdata0))
        return static_cast<void*>(this);
    return QMenu::qt_metacast(_clname);
}

int ProtocolPreferencesMenu::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMenu::qt_metacall(_c, _id, _a);
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
void ProtocolPreferencesMenu::showProtocolPreferences(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void ProtocolPreferencesMenu::editProtocolPreference(preference * _t1, pref_module * _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
