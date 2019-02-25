/****************************************************************************
** Meta object code from reading C++ file 'preference_editor_frame.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/preference_editor_frame.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'preference_editor_frame.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_PreferenceEditorFrame_t {
    QByteArrayData data[18];
    char stringdata0[333];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_PreferenceEditorFrame_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_PreferenceEditorFrame_t qt_meta_stringdata_PreferenceEditorFrame = {
    {
QT_MOC_LITERAL(0, 0, 21), // "PreferenceEditorFrame"
QT_MOC_LITERAL(1, 22, 23), // "showProtocolPreferences"
QT_MOC_LITERAL(2, 46, 0), // ""
QT_MOC_LITERAL(3, 47, 11), // "module_name"
QT_MOC_LITERAL(4, 59, 22), // "pushFilterSyntaxStatus"
QT_MOC_LITERAL(5, 82, 14), // "editPreference"
QT_MOC_LITERAL(6, 97, 11), // "preference*"
QT_MOC_LITERAL(7, 109, 4), // "pref"
QT_MOC_LITERAL(8, 114, 12), // "pref_module*"
QT_MOC_LITERAL(9, 127, 6), // "module"
QT_MOC_LITERAL(10, 134, 22), // "uintLineEditTextEdited"
QT_MOC_LITERAL(11, 157, 7), // "new_str"
QT_MOC_LITERAL(12, 165, 24), // "stringLineEditTextEdited"
QT_MOC_LITERAL(13, 190, 23), // "rangeLineEditTextEdited"
QT_MOC_LITERAL(14, 214, 38), // "on_modulePreferencesToolButto..."
QT_MOC_LITERAL(15, 253, 35), // "on_preferenceLineEdit_returnP..."
QT_MOC_LITERAL(16, 289, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(17, 311, 21) // "on_buttonBox_rejected"

    },
    "PreferenceEditorFrame\0showProtocolPreferences\0"
    "\0module_name\0pushFilterSyntaxStatus\0"
    "editPreference\0preference*\0pref\0"
    "pref_module*\0module\0uintLineEditTextEdited\0"
    "new_str\0stringLineEditTextEdited\0"
    "rangeLineEditTextEdited\0"
    "on_modulePreferencesToolButton_clicked\0"
    "on_preferenceLineEdit_returnPressed\0"
    "on_buttonBox_accepted\0on_buttonBox_rejected"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_PreferenceEditorFrame[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      12,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   74,    2, 0x06 /* Public */,
       4,    1,   77,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    2,   80,    2, 0x0a /* Public */,
       5,    1,   85,    2, 0x2a /* Public | MethodCloned */,
       5,    0,   88,    2, 0x2a /* Public | MethodCloned */,
      10,    1,   89,    2, 0x08 /* Private */,
      12,    1,   92,    2, 0x08 /* Private */,
      13,    1,   95,    2, 0x08 /* Private */,
      14,    0,   98,    2, 0x08 /* Private */,
      15,    0,   99,    2, 0x08 /* Private */,
      16,    0,  100,    2, 0x08 /* Private */,
      17,    0,  101,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    2,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6, 0x80000000 | 8,    7,    9,
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void PreferenceEditorFrame::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        PreferenceEditorFrame *_t = static_cast<PreferenceEditorFrame *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->showProtocolPreferences((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->pushFilterSyntaxStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: _t->editPreference((*reinterpret_cast< preference*(*)>(_a[1])),(*reinterpret_cast< pref_module*(*)>(_a[2]))); break;
        case 3: _t->editPreference((*reinterpret_cast< preference*(*)>(_a[1]))); break;
        case 4: _t->editPreference(); break;
        case 5: _t->uintLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 6: _t->stringLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 7: _t->rangeLineEditTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 8: _t->on_modulePreferencesToolButton_clicked(); break;
        case 9: _t->on_preferenceLineEdit_returnPressed(); break;
        case 10: _t->on_buttonBox_accepted(); break;
        case 11: _t->on_buttonBox_rejected(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (PreferenceEditorFrame::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PreferenceEditorFrame::showProtocolPreferences)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (PreferenceEditorFrame::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PreferenceEditorFrame::pushFilterSyntaxStatus)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject PreferenceEditorFrame::staticMetaObject = { {
    &AccordionFrame::staticMetaObject,
    qt_meta_stringdata_PreferenceEditorFrame.data,
    qt_meta_data_PreferenceEditorFrame,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *PreferenceEditorFrame::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PreferenceEditorFrame::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_PreferenceEditorFrame.stringdata0))
        return static_cast<void*>(this);
    return AccordionFrame::qt_metacast(_clname);
}

int PreferenceEditorFrame::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = AccordionFrame::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 12)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void PreferenceEditorFrame::showProtocolPreferences(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void PreferenceEditorFrame::pushFilterSyntaxStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
