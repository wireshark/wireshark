/****************************************************************************
** Meta object code from reading C++ file 'sctp_graph_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/sctp_graph_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'sctp_graph_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_SCTPGraphDialog_t {
    QByteArrayData data[17];
    char stringdata0[262];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SCTPGraphDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SCTPGraphDialog_t qt_meta_stringdata_SCTPGraphDialog = {
    {
QT_MOC_LITERAL(0, 0, 15), // "SCTPGraphDialog"
QT_MOC_LITERAL(1, 16, 14), // "setCaptureFile"
QT_MOC_LITERAL(2, 31, 0), // ""
QT_MOC_LITERAL(3, 32, 13), // "capture_file*"
QT_MOC_LITERAL(4, 46, 2), // "cf"
QT_MOC_LITERAL(5, 49, 21), // "on_pushButton_clicked"
QT_MOC_LITERAL(6, 71, 23), // "on_pushButton_2_clicked"
QT_MOC_LITERAL(7, 95, 23), // "on_pushButton_3_clicked"
QT_MOC_LITERAL(8, 119, 23), // "on_pushButton_4_clicked"
QT_MOC_LITERAL(9, 143, 12), // "graphClicked"
QT_MOC_LITERAL(10, 156, 21), // "QCPAbstractPlottable*"
QT_MOC_LITERAL(11, 178, 9), // "plottable"
QT_MOC_LITERAL(12, 188, 12), // "QMouseEvent*"
QT_MOC_LITERAL(13, 201, 5), // "event"
QT_MOC_LITERAL(14, 207, 21), // "on_saveButton_clicked"
QT_MOC_LITERAL(15, 229, 27), // "on_relativeTsn_stateChanged"
QT_MOC_LITERAL(16, 257, 4) // "arg1"

    },
    "SCTPGraphDialog\0setCaptureFile\0\0"
    "capture_file*\0cf\0on_pushButton_clicked\0"
    "on_pushButton_2_clicked\0on_pushButton_3_clicked\0"
    "on_pushButton_4_clicked\0graphClicked\0"
    "QCPAbstractPlottable*\0plottable\0"
    "QMouseEvent*\0event\0on_saveButton_clicked\0"
    "on_relativeTsn_stateChanged\0arg1"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SCTPGraphDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   54,    2, 0x0a /* Public */,
       5,    0,   57,    2, 0x08 /* Private */,
       6,    0,   58,    2, 0x08 /* Private */,
       7,    0,   59,    2, 0x08 /* Private */,
       8,    0,   60,    2, 0x08 /* Private */,
       9,    2,   61,    2, 0x08 /* Private */,
      14,    0,   66,    2, 0x08 /* Private */,
      15,    1,   67,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 10, 0x80000000 | 12,   11,   13,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   16,

       0        // eod
};

void SCTPGraphDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SCTPGraphDialog *_t = static_cast<SCTPGraphDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 1: _t->on_pushButton_clicked(); break;
        case 2: _t->on_pushButton_2_clicked(); break;
        case 3: _t->on_pushButton_3_clicked(); break;
        case 4: _t->on_pushButton_4_clicked(); break;
        case 5: _t->graphClicked((*reinterpret_cast< QCPAbstractPlottable*(*)>(_a[1])),(*reinterpret_cast< QMouseEvent*(*)>(_a[2]))); break;
        case 6: _t->on_saveButton_clicked(); break;
        case 7: _t->on_relativeTsn_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject SCTPGraphDialog::staticMetaObject = { {
    &QDialog::staticMetaObject,
    qt_meta_stringdata_SCTPGraphDialog.data,
    qt_meta_data_SCTPGraphDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *SCTPGraphDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SCTPGraphDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_SCTPGraphDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int SCTPGraphDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
