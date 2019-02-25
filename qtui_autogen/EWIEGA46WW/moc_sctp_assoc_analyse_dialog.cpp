/****************************************************************************
** Meta object code from reading C++ file 'sctp_assoc_analyse_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/sctp_assoc_analyse_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'sctp_assoc_analyse_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_SCTPAssocAnalyseDialog_t {
    QByteArrayData data[16];
    char stringdata0[287];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SCTPAssocAnalyseDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SCTPAssocAnalyseDialog_t qt_meta_stringdata_SCTPAssocAnalyseDialog = {
    {
QT_MOC_LITERAL(0, 0, 22), // "SCTPAssocAnalyseDialog"
QT_MOC_LITERAL(1, 23, 13), // "filterPackets"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 10), // "new_filter"
QT_MOC_LITERAL(4, 49, 5), // "force"
QT_MOC_LITERAL(5, 55, 14), // "setCaptureFile"
QT_MOC_LITERAL(6, 70, 13), // "capture_file*"
QT_MOC_LITERAL(7, 84, 2), // "cf"
QT_MOC_LITERAL(8, 87, 21), // "on_GraphTSN_2_clicked"
QT_MOC_LITERAL(9, 109, 21), // "on_GraphTSN_1_clicked"
QT_MOC_LITERAL(10, 131, 32), // "on_chunkStatisticsButton_clicked"
QT_MOC_LITERAL(11, 164, 26), // "on_setFilterButton_clicked"
QT_MOC_LITERAL(12, 191, 23), // "on_GraphBytes_1_clicked"
QT_MOC_LITERAL(13, 215, 23), // "on_GraphBytes_2_clicked"
QT_MOC_LITERAL(14, 239, 23), // "on_GraphArwnd_1_clicked"
QT_MOC_LITERAL(15, 263, 23) // "on_GraphArwnd_2_clicked"

    },
    "SCTPAssocAnalyseDialog\0filterPackets\0"
    "\0new_filter\0force\0setCaptureFile\0"
    "capture_file*\0cf\0on_GraphTSN_2_clicked\0"
    "on_GraphTSN_1_clicked\0"
    "on_chunkStatisticsButton_clicked\0"
    "on_setFilterButton_clicked\0"
    "on_GraphBytes_1_clicked\0on_GraphBytes_2_clicked\0"
    "on_GraphArwnd_1_clicked\0on_GraphArwnd_2_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SCTPAssocAnalyseDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      10,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   64,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    1,   69,    2, 0x0a /* Public */,
       8,    0,   72,    2, 0x08 /* Private */,
       9,    0,   73,    2, 0x08 /* Private */,
      10,    0,   74,    2, 0x08 /* Private */,
      11,    0,   75,    2, 0x08 /* Private */,
      12,    0,   76,    2, 0x08 /* Private */,
      13,    0,   77,    2, 0x08 /* Private */,
      14,    0,   78,    2, 0x08 /* Private */,
      15,    0,   79,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    3,    4,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void SCTPAssocAnalyseDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SCTPAssocAnalyseDialog *_t = static_cast<SCTPAssocAnalyseDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterPackets((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 1: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 2: _t->on_GraphTSN_2_clicked(); break;
        case 3: _t->on_GraphTSN_1_clicked(); break;
        case 4: _t->on_chunkStatisticsButton_clicked(); break;
        case 5: _t->on_setFilterButton_clicked(); break;
        case 6: _t->on_GraphBytes_1_clicked(); break;
        case 7: _t->on_GraphBytes_2_clicked(); break;
        case 8: _t->on_GraphArwnd_1_clicked(); break;
        case 9: _t->on_GraphArwnd_2_clicked(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (SCTPAssocAnalyseDialog::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&SCTPAssocAnalyseDialog::filterPackets)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject SCTPAssocAnalyseDialog::staticMetaObject = { {
    &QDialog::staticMetaObject,
    qt_meta_stringdata_SCTPAssocAnalyseDialog.data,
    qt_meta_data_SCTPAssocAnalyseDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *SCTPAssocAnalyseDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SCTPAssocAnalyseDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_SCTPAssocAnalyseDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int SCTPAssocAnalyseDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void SCTPAssocAnalyseDialog::filterPackets(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
