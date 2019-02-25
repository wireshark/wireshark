/****************************************************************************
** Meta object code from reading C++ file 'protocol_hierarchy_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/protocol_hierarchy_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'protocol_hierarchy_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ProtocolHierarchyDialog_t {
    QByteArrayData data[14];
    char stringdata0[233];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ProtocolHierarchyDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ProtocolHierarchyDialog_t qt_meta_stringdata_ProtocolHierarchyDialog = {
    {
QT_MOC_LITERAL(0, 0, 23), // "ProtocolHierarchyDialog"
QT_MOC_LITERAL(1, 24, 12), // "filterAction"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 6), // "filter"
QT_MOC_LITERAL(4, 45, 20), // "FilterAction::Action"
QT_MOC_LITERAL(5, 66, 6), // "action"
QT_MOC_LITERAL(6, 73, 24), // "FilterAction::ActionType"
QT_MOC_LITERAL(7, 98, 4), // "type"
QT_MOC_LITERAL(8, 103, 17), // "showProtoHierMenu"
QT_MOC_LITERAL(9, 121, 3), // "pos"
QT_MOC_LITERAL(10, 125, 21), // "filterActionTriggered"
QT_MOC_LITERAL(11, 147, 28), // "on_actionCopyAsCsv_triggered"
QT_MOC_LITERAL(12, 176, 29), // "on_actionCopyAsYaml_triggered"
QT_MOC_LITERAL(13, 206, 26) // "on_buttonBox_helpRequested"

    },
    "ProtocolHierarchyDialog\0filterAction\0"
    "\0filter\0FilterAction::Action\0action\0"
    "FilterAction::ActionType\0type\0"
    "showProtoHierMenu\0pos\0filterActionTriggered\0"
    "on_actionCopyAsCsv_triggered\0"
    "on_actionCopyAsYaml_triggered\0"
    "on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ProtocolHierarchyDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    3,   44,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    1,   51,    2, 0x08 /* Private */,
      10,    0,   54,    2, 0x08 /* Private */,
      11,    0,   55,    2, 0x08 /* Private */,
      12,    0,   56,    2, 0x08 /* Private */,
      13,    0,   57,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, 0x80000000 | 4, 0x80000000 | 6,    3,    5,    7,

 // slots: parameters
    QMetaType::Void, QMetaType::QPoint,    9,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ProtocolHierarchyDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ProtocolHierarchyDialog *_t = static_cast<ProtocolHierarchyDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterAction((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< FilterAction::Action(*)>(_a[2])),(*reinterpret_cast< FilterAction::ActionType(*)>(_a[3]))); break;
        case 1: _t->showProtoHierMenu((*reinterpret_cast< QPoint(*)>(_a[1]))); break;
        case 2: _t->filterActionTriggered(); break;
        case 3: _t->on_actionCopyAsCsv_triggered(); break;
        case 4: _t->on_actionCopyAsYaml_triggered(); break;
        case 5: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ProtocolHierarchyDialog::*)(QString , FilterAction::Action , FilterAction::ActionType );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ProtocolHierarchyDialog::filterAction)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ProtocolHierarchyDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_ProtocolHierarchyDialog.data,
    qt_meta_data_ProtocolHierarchyDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ProtocolHierarchyDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ProtocolHierarchyDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ProtocolHierarchyDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int ProtocolHierarchyDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void ProtocolHierarchyDialog::filterAction(QString _t1, FilterAction::Action _t2, FilterAction::ActionType _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
