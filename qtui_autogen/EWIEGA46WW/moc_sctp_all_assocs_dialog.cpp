/****************************************************************************
** Meta object code from reading C++ file 'sctp_all_assocs_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/sctp_all_assocs_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'sctp_all_assocs_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_SCTPAllAssocsDialog_t {
    QByteArrayData data[11];
    char stringdata0[152];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SCTPAllAssocsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SCTPAllAssocsDialog_t qt_meta_stringdata_SCTPAllAssocsDialog = {
    {
QT_MOC_LITERAL(0, 0, 19), // "SCTPAllAssocsDialog"
QT_MOC_LITERAL(1, 20, 13), // "filterPackets"
QT_MOC_LITERAL(2, 34, 0), // ""
QT_MOC_LITERAL(3, 35, 10), // "new_filter"
QT_MOC_LITERAL(4, 46, 5), // "force"
QT_MOC_LITERAL(5, 52, 14), // "setCaptureFile"
QT_MOC_LITERAL(6, 67, 13), // "capture_file*"
QT_MOC_LITERAL(7, 81, 2), // "cf"
QT_MOC_LITERAL(8, 84, 24), // "on_analyseButton_clicked"
QT_MOC_LITERAL(9, 109, 26), // "on_setFilterButton_clicked"
QT_MOC_LITERAL(10, 136, 15) // "getSelectedItem"

    },
    "SCTPAllAssocsDialog\0filterPackets\0\0"
    "new_filter\0force\0setCaptureFile\0"
    "capture_file*\0cf\0on_analyseButton_clicked\0"
    "on_setFilterButton_clicked\0getSelectedItem"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SCTPAllAssocsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       5,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   39,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   44,    2, 0x0a /* Public */,
       8,    0,   47,    2, 0x08 /* Private */,
       9,    0,   48,    2, 0x08 /* Private */,
      10,    0,   49,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    3,    4,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void SCTPAllAssocsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SCTPAllAssocsDialog *_t = static_cast<SCTPAllAssocsDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterPackets((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 1: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 2: _t->on_analyseButton_clicked(); break;
        case 3: _t->on_setFilterButton_clicked(); break;
        case 4: _t->getSelectedItem(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (SCTPAllAssocsDialog::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SCTPAllAssocsDialog::filterPackets)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject SCTPAllAssocsDialog::staticMetaObject = { {
    &QDialog::staticMetaObject,
    qt_meta_stringdata_SCTPAllAssocsDialog.data,
    qt_meta_data_SCTPAllAssocsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *SCTPAllAssocsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SCTPAllAssocsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_SCTPAllAssocsDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int SCTPAllAssocsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void SCTPAllAssocsDialog::filterPackets(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
