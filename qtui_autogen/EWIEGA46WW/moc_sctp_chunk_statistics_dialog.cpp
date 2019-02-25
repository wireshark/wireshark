/****************************************************************************
** Meta object code from reading C++ file 'sctp_chunk_statistics_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/sctp_chunk_statistics_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'sctp_chunk_statistics_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_SCTPChunkStatisticsDialog_t {
    QByteArrayData data[12];
    char stringdata0[233];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SCTPChunkStatisticsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SCTPChunkStatisticsDialog_t qt_meta_stringdata_SCTPChunkStatisticsDialog = {
    {
QT_MOC_LITERAL(0, 0, 25), // "SCTPChunkStatisticsDialog"
QT_MOC_LITERAL(1, 26, 14), // "setCaptureFile"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 13), // "capture_file*"
QT_MOC_LITERAL(4, 56, 2), // "cf"
QT_MOC_LITERAL(5, 59, 21), // "on_pushButton_clicked"
QT_MOC_LITERAL(6, 81, 32), // "on_actionHideChunkType_triggered"
QT_MOC_LITERAL(7, 114, 39), // "on_actionChunkTypePreferences..."
QT_MOC_LITERAL(8, 154, 16), // "contextMenuEvent"
QT_MOC_LITERAL(9, 171, 18), // "QContextMenuEvent*"
QT_MOC_LITERAL(10, 190, 5), // "event"
QT_MOC_LITERAL(11, 196, 36) // "on_actionShowAllChunkTypes_tr..."

    },
    "SCTPChunkStatisticsDialog\0setCaptureFile\0"
    "\0capture_file*\0cf\0on_pushButton_clicked\0"
    "on_actionHideChunkType_triggered\0"
    "on_actionChunkTypePreferences_triggered\0"
    "contextMenuEvent\0QContextMenuEvent*\0"
    "event\0on_actionShowAllChunkTypes_triggered"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SCTPChunkStatisticsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x0a /* Public */,
       5,    0,   47,    2, 0x08 /* Private */,
       6,    0,   48,    2, 0x08 /* Private */,
       7,    0,   49,    2, 0x08 /* Private */,
       8,    1,   50,    2, 0x08 /* Private */,
      11,    0,   53,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 3,    4,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void,

       0        // eod
};

void SCTPChunkStatisticsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SCTPChunkStatisticsDialog *_t = static_cast<SCTPChunkStatisticsDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 1: _t->on_pushButton_clicked(); break;
        case 2: _t->on_actionHideChunkType_triggered(); break;
        case 3: _t->on_actionChunkTypePreferences_triggered(); break;
        case 4: _t->contextMenuEvent((*reinterpret_cast< QContextMenuEvent*(*)>(_a[1]))); break;
        case 5: _t->on_actionShowAllChunkTypes_triggered(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject SCTPChunkStatisticsDialog::staticMetaObject = { {
    &QDialog::staticMetaObject,
    qt_meta_stringdata_SCTPChunkStatisticsDialog.data,
    qt_meta_data_SCTPChunkStatisticsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *SCTPChunkStatisticsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SCTPChunkStatisticsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_SCTPChunkStatisticsDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int SCTPChunkStatisticsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
