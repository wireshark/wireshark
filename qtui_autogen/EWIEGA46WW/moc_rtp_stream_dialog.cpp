/****************************************************************************
** Meta object code from reading C++ file 'rtp_stream_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/rtp_stream_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'rtp_stream_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_RtpStreamDialog_t {
    QByteArrayData data[25];
    char stringdata0[505];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_RtpStreamDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_RtpStreamDialog_t qt_meta_stringdata_RtpStreamDialog = {
    {
QT_MOC_LITERAL(0, 0, 15), // "RtpStreamDialog"
QT_MOC_LITERAL(1, 16, 13), // "packetsMarked"
QT_MOC_LITERAL(2, 30, 0), // ""
QT_MOC_LITERAL(3, 31, 12), // "updateFilter"
QT_MOC_LITERAL(4, 44, 6), // "filter"
QT_MOC_LITERAL(5, 51, 5), // "force"
QT_MOC_LITERAL(6, 57, 10), // "goToPacket"
QT_MOC_LITERAL(7, 68, 10), // "packet_num"
QT_MOC_LITERAL(8, 79, 18), // "captureFileClosing"
QT_MOC_LITERAL(9, 98, 14), // "showStreamMenu"
QT_MOC_LITERAL(10, 113, 3), // "pos"
QT_MOC_LITERAL(11, 117, 28), // "on_actionCopyAsCsv_triggered"
QT_MOC_LITERAL(12, 146, 29), // "on_actionCopyAsYaml_triggered"
QT_MOC_LITERAL(13, 176, 30), // "on_actionFindReverse_triggered"
QT_MOC_LITERAL(14, 207, 28), // "on_actionGoToSetup_triggered"
QT_MOC_LITERAL(15, 236, 30), // "on_actionMarkPackets_triggered"
QT_MOC_LITERAL(16, 267, 32), // "on_actionPrepareFilter_triggered"
QT_MOC_LITERAL(17, 300, 29), // "on_actionSelectNone_triggered"
QT_MOC_LITERAL(18, 330, 40), // "on_streamTreeWidget_itemSelec..."
QT_MOC_LITERAL(19, 371, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(20, 398, 20), // "on_buttonBox_clicked"
QT_MOC_LITERAL(21, 419, 16), // "QAbstractButton*"
QT_MOC_LITERAL(22, 436, 6), // "button"
QT_MOC_LITERAL(23, 443, 34), // "on_actionExportAsRtpDump_trig..."
QT_MOC_LITERAL(24, 478, 26) // "on_actionAnalyze_triggered"

    },
    "RtpStreamDialog\0packetsMarked\0\0"
    "updateFilter\0filter\0force\0goToPacket\0"
    "packet_num\0captureFileClosing\0"
    "showStreamMenu\0pos\0on_actionCopyAsCsv_triggered\0"
    "on_actionCopyAsYaml_triggered\0"
    "on_actionFindReverse_triggered\0"
    "on_actionGoToSetup_triggered\0"
    "on_actionMarkPackets_triggered\0"
    "on_actionPrepareFilter_triggered\0"
    "on_actionSelectNone_triggered\0"
    "on_streamTreeWidget_itemSelectionChanged\0"
    "on_buttonBox_helpRequested\0"
    "on_buttonBox_clicked\0QAbstractButton*\0"
    "button\0on_actionExportAsRtpDump_triggered\0"
    "on_actionAnalyze_triggered"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_RtpStreamDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      18,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,  104,    2, 0x06 /* Public */,
       3,    2,  105,    2, 0x06 /* Public */,
       3,    1,  110,    2, 0x26 /* Public | MethodCloned */,
       6,    1,  113,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    0,  116,    2, 0x08 /* Private */,
       9,    1,  117,    2, 0x08 /* Private */,
      11,    0,  120,    2, 0x08 /* Private */,
      12,    0,  121,    2, 0x08 /* Private */,
      13,    0,  122,    2, 0x08 /* Private */,
      14,    0,  123,    2, 0x08 /* Private */,
      15,    0,  124,    2, 0x08 /* Private */,
      16,    0,  125,    2, 0x08 /* Private */,
      17,    0,  126,    2, 0x08 /* Private */,
      18,    0,  127,    2, 0x08 /* Private */,
      19,    0,  128,    2, 0x08 /* Private */,
      20,    1,  129,    2, 0x08 /* Private */,
      23,    0,  132,    2, 0x08 /* Private */,
      24,    0,  133,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    4,    5,
    QMetaType::Void, QMetaType::QString,    4,
    QMetaType::Void, QMetaType::Int,    7,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,   10,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 21,   22,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void RtpStreamDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        RtpStreamDialog *_t = static_cast<RtpStreamDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->packetsMarked(); break;
        case 1: _t->updateFilter((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 2: _t->updateFilter((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->goToPacket((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->captureFileClosing(); break;
        case 5: _t->showStreamMenu((*reinterpret_cast< QPoint(*)>(_a[1]))); break;
        case 6: _t->on_actionCopyAsCsv_triggered(); break;
        case 7: _t->on_actionCopyAsYaml_triggered(); break;
        case 8: _t->on_actionFindReverse_triggered(); break;
        case 9: _t->on_actionGoToSetup_triggered(); break;
        case 10: _t->on_actionMarkPackets_triggered(); break;
        case 11: _t->on_actionPrepareFilter_triggered(); break;
        case 12: _t->on_actionSelectNone_triggered(); break;
        case 13: _t->on_streamTreeWidget_itemSelectionChanged(); break;
        case 14: _t->on_buttonBox_helpRequested(); break;
        case 15: _t->on_buttonBox_clicked((*reinterpret_cast< QAbstractButton*(*)>(_a[1]))); break;
        case 16: _t->on_actionExportAsRtpDump_triggered(); break;
        case 17: _t->on_actionAnalyze_triggered(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 15:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAbstractButton* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (RtpStreamDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpStreamDialog::packetsMarked)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (RtpStreamDialog::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpStreamDialog::updateFilter)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (RtpStreamDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpStreamDialog::goToPacket)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject RtpStreamDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_RtpStreamDialog.data,
    qt_meta_data_RtpStreamDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *RtpStreamDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RtpStreamDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_RtpStreamDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int RtpStreamDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 18)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 18;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 18)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 18;
    }
    return _id;
}

// SIGNAL 0
void RtpStreamDialog::packetsMarked()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void RtpStreamDialog::updateFilter(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 3
void RtpStreamDialog::goToPacket(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
