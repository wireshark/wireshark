/****************************************************************************
** Meta object code from reading C++ file 'tap_parameter_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/tap_parameter_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'tap_parameter_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_TapParameterDialog_t {
    QByteArrayData data[16];
    char stringdata0[273];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_TapParameterDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_TapParameterDialog_t qt_meta_stringdata_TapParameterDialog = {
    {
QT_MOC_LITERAL(0, 0, 18), // "TapParameterDialog"
QT_MOC_LITERAL(1, 19, 12), // "filterAction"
QT_MOC_LITERAL(2, 32, 0), // ""
QT_MOC_LITERAL(3, 33, 6), // "filter"
QT_MOC_LITERAL(4, 40, 20), // "FilterAction::Action"
QT_MOC_LITERAL(5, 61, 6), // "action"
QT_MOC_LITERAL(6, 68, 24), // "FilterAction::ActionType"
QT_MOC_LITERAL(7, 93, 4), // "type"
QT_MOC_LITERAL(8, 98, 12), // "updateFilter"
QT_MOC_LITERAL(9, 111, 21), // "filterActionTriggered"
QT_MOC_LITERAL(10, 133, 13), // "updateWidgets"
QT_MOC_LITERAL(11, 147, 8), // "fillTree"
QT_MOC_LITERAL(12, 156, 28), // "on_applyFilterButton_clicked"
QT_MOC_LITERAL(13, 185, 34), // "on_actionCopyToClipboard_trig..."
QT_MOC_LITERAL(14, 220, 25), // "on_actionSaveAs_triggered"
QT_MOC_LITERAL(15, 246, 26) // "on_buttonBox_helpRequested"

    },
    "TapParameterDialog\0filterAction\0\0"
    "filter\0FilterAction::Action\0action\0"
    "FilterAction::ActionType\0type\0"
    "updateFilter\0filterActionTriggered\0"
    "updateWidgets\0fillTree\0"
    "on_applyFilterButton_clicked\0"
    "on_actionCopyToClipboard_triggered\0"
    "on_actionSaveAs_triggered\0"
    "on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_TapParameterDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    3,   59,    2, 0x06 /* Public */,
       8,    1,   66,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    0,   69,    2, 0x09 /* Protected */,
      10,    0,   70,    2, 0x09 /* Protected */,
      11,    0,   71,    2, 0x08 /* Private */,
      12,    0,   72,    2, 0x08 /* Private */,
      13,    0,   73,    2, 0x08 /* Private */,
      14,    0,   74,    2, 0x08 /* Private */,
      15,    0,   75,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, 0x80000000 | 4, 0x80000000 | 6,    3,    5,    7,
    QMetaType::Void, QMetaType::QString,    3,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void TapParameterDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TapParameterDialog *_t = static_cast<TapParameterDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterAction((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< FilterAction::Action(*)>(_a[2])),(*reinterpret_cast< FilterAction::ActionType(*)>(_a[3]))); break;
        case 1: _t->updateFilter((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 2: _t->filterActionTriggered(); break;
        case 3: _t->updateWidgets(); break;
        case 4: _t->fillTree(); break;
        case 5: _t->on_applyFilterButton_clicked(); break;
        case 6: _t->on_actionCopyToClipboard_triggered(); break;
        case 7: _t->on_actionSaveAs_triggered(); break;
        case 8: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TapParameterDialog::*)(QString , FilterAction::Action , FilterAction::ActionType );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TapParameterDialog::filterAction)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (TapParameterDialog::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TapParameterDialog::updateFilter)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject TapParameterDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_TapParameterDialog.data,
    qt_meta_data_TapParameterDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *TapParameterDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TapParameterDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_TapParameterDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int TapParameterDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 9;
    }
    return _id;
}

// SIGNAL 0
void TapParameterDialog::filterAction(QString _t1, FilterAction::Action _t2, FilterAction::ActionType _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void TapParameterDialog::updateFilter(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
