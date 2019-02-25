/****************************************************************************
** Meta object code from reading C++ file 'rtp_analysis_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/rtp_analysis_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'rtp_analysis_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_RtpAnalysisDialog_t {
    QByteArrayData data[36];
    char stringdata0[902];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_RtpAnalysisDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_RtpAnalysisDialog_t qt_meta_stringdata_RtpAnalysisDialog = {
    {
QT_MOC_LITERAL(0, 0, 17), // "RtpAnalysisDialog"
QT_MOC_LITERAL(1, 18, 10), // "goToPacket"
QT_MOC_LITERAL(2, 29, 0), // ""
QT_MOC_LITERAL(3, 30, 10), // "packet_num"
QT_MOC_LITERAL(4, 41, 13), // "updateWidgets"
QT_MOC_LITERAL(5, 55, 29), // "on_actionGoToPacket_triggered"
QT_MOC_LITERAL(6, 85, 30), // "on_actionNextProblem_triggered"
QT_MOC_LITERAL(7, 116, 26), // "on_fJitterCheckBox_toggled"
QT_MOC_LITERAL(8, 143, 7), // "checked"
QT_MOC_LITERAL(9, 151, 24), // "on_fDiffCheckBox_toggled"
QT_MOC_LITERAL(10, 176, 25), // "on_fDeltaCheckBox_toggled"
QT_MOC_LITERAL(11, 202, 26), // "on_rJitterCheckBox_toggled"
QT_MOC_LITERAL(12, 229, 24), // "on_rDiffCheckBox_toggled"
QT_MOC_LITERAL(13, 254, 25), // "on_rDeltaCheckBox_toggled"
QT_MOC_LITERAL(14, 280, 34), // "on_actionSaveAudioUnsync_trig..."
QT_MOC_LITERAL(15, 315, 41), // "on_actionSaveForwardAudioUnsy..."
QT_MOC_LITERAL(16, 357, 41), // "on_actionSaveReverseAudioUnsy..."
QT_MOC_LITERAL(17, 399, 38), // "on_actionSaveAudioSyncStream_..."
QT_MOC_LITERAL(18, 438, 45), // "on_actionSaveForwardAudioSync..."
QT_MOC_LITERAL(19, 484, 45), // "on_actionSaveReverseAudioSync..."
QT_MOC_LITERAL(20, 530, 36), // "on_actionSaveAudioSyncFile_tr..."
QT_MOC_LITERAL(21, 567, 43), // "on_actionSaveForwardAudioSync..."
QT_MOC_LITERAL(22, 611, 43), // "on_actionSaveReverseAudioSync..."
QT_MOC_LITERAL(23, 655, 26), // "on_actionSaveCsv_triggered"
QT_MOC_LITERAL(24, 682, 33), // "on_actionSaveForwardCsv_trigg..."
QT_MOC_LITERAL(25, 716, 33), // "on_actionSaveReverseCsv_trigg..."
QT_MOC_LITERAL(26, 750, 28), // "on_actionSaveGraph_triggered"
QT_MOC_LITERAL(27, 779, 20), // "on_buttonBox_clicked"
QT_MOC_LITERAL(28, 800, 16), // "QAbstractButton*"
QT_MOC_LITERAL(29, 817, 6), // "button"
QT_MOC_LITERAL(30, 824, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(31, 851, 14), // "showStreamMenu"
QT_MOC_LITERAL(32, 866, 3), // "pos"
QT_MOC_LITERAL(33, 870, 12), // "graphClicked"
QT_MOC_LITERAL(34, 883, 12), // "QMouseEvent*"
QT_MOC_LITERAL(35, 896, 5) // "event"

    },
    "RtpAnalysisDialog\0goToPacket\0\0packet_num\0"
    "updateWidgets\0on_actionGoToPacket_triggered\0"
    "on_actionNextProblem_triggered\0"
    "on_fJitterCheckBox_toggled\0checked\0"
    "on_fDiffCheckBox_toggled\0"
    "on_fDeltaCheckBox_toggled\0"
    "on_rJitterCheckBox_toggled\0"
    "on_rDiffCheckBox_toggled\0"
    "on_rDeltaCheckBox_toggled\0"
    "on_actionSaveAudioUnsync_triggered\0"
    "on_actionSaveForwardAudioUnsync_triggered\0"
    "on_actionSaveReverseAudioUnsync_triggered\0"
    "on_actionSaveAudioSyncStream_triggered\0"
    "on_actionSaveForwardAudioSyncStream_triggered\0"
    "on_actionSaveReverseAudioSyncStream_triggered\0"
    "on_actionSaveAudioSyncFile_triggered\0"
    "on_actionSaveForwardAudioSyncFile_triggered\0"
    "on_actionSaveReverseAudioSyncFile_triggered\0"
    "on_actionSaveCsv_triggered\0"
    "on_actionSaveForwardCsv_triggered\0"
    "on_actionSaveReverseCsv_triggered\0"
    "on_actionSaveGraph_triggered\0"
    "on_buttonBox_clicked\0QAbstractButton*\0"
    "button\0on_buttonBox_helpRequested\0"
    "showStreamMenu\0pos\0graphClicked\0"
    "QMouseEvent*\0event"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_RtpAnalysisDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      27,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,  149,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    0,  152,    2, 0x09 /* Protected */,
       5,    0,  153,    2, 0x08 /* Private */,
       6,    0,  154,    2, 0x08 /* Private */,
       7,    1,  155,    2, 0x08 /* Private */,
       9,    1,  158,    2, 0x08 /* Private */,
      10,    1,  161,    2, 0x08 /* Private */,
      11,    1,  164,    2, 0x08 /* Private */,
      12,    1,  167,    2, 0x08 /* Private */,
      13,    1,  170,    2, 0x08 /* Private */,
      14,    0,  173,    2, 0x08 /* Private */,
      15,    0,  174,    2, 0x08 /* Private */,
      16,    0,  175,    2, 0x08 /* Private */,
      17,    0,  176,    2, 0x08 /* Private */,
      18,    0,  177,    2, 0x08 /* Private */,
      19,    0,  178,    2, 0x08 /* Private */,
      20,    0,  179,    2, 0x08 /* Private */,
      21,    0,  180,    2, 0x08 /* Private */,
      22,    0,  181,    2, 0x08 /* Private */,
      23,    0,  182,    2, 0x08 /* Private */,
      24,    0,  183,    2, 0x08 /* Private */,
      25,    0,  184,    2, 0x08 /* Private */,
      26,    0,  185,    2, 0x08 /* Private */,
      27,    1,  186,    2, 0x08 /* Private */,
      30,    0,  189,    2, 0x08 /* Private */,
      31,    1,  190,    2, 0x08 /* Private */,
      33,    1,  193,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void, QMetaType::Bool,    8,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 28,   29,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,   32,
    QMetaType::Void, 0x80000000 | 34,   35,

       0        // eod
};

void RtpAnalysisDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        RtpAnalysisDialog *_t = static_cast<RtpAnalysisDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->goToPacket((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->updateWidgets(); break;
        case 2: _t->on_actionGoToPacket_triggered(); break;
        case 3: _t->on_actionNextProblem_triggered(); break;
        case 4: _t->on_fJitterCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->on_fDiffCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->on_fDeltaCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->on_rJitterCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 8: _t->on_rDiffCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 9: _t->on_rDeltaCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 10: _t->on_actionSaveAudioUnsync_triggered(); break;
        case 11: _t->on_actionSaveForwardAudioUnsync_triggered(); break;
        case 12: _t->on_actionSaveReverseAudioUnsync_triggered(); break;
        case 13: _t->on_actionSaveAudioSyncStream_triggered(); break;
        case 14: _t->on_actionSaveForwardAudioSyncStream_triggered(); break;
        case 15: _t->on_actionSaveReverseAudioSyncStream_triggered(); break;
        case 16: _t->on_actionSaveAudioSyncFile_triggered(); break;
        case 17: _t->on_actionSaveForwardAudioSyncFile_triggered(); break;
        case 18: _t->on_actionSaveReverseAudioSyncFile_triggered(); break;
        case 19: _t->on_actionSaveCsv_triggered(); break;
        case 20: _t->on_actionSaveForwardCsv_triggered(); break;
        case 21: _t->on_actionSaveReverseCsv_triggered(); break;
        case 22: _t->on_actionSaveGraph_triggered(); break;
        case 23: _t->on_buttonBox_clicked((*reinterpret_cast< QAbstractButton*(*)>(_a[1]))); break;
        case 24: _t->on_buttonBox_helpRequested(); break;
        case 25: _t->showStreamMenu((*reinterpret_cast< QPoint(*)>(_a[1]))); break;
        case 26: _t->graphClicked((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 23:
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
            using _t = void (RtpAnalysisDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpAnalysisDialog::goToPacket)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject RtpAnalysisDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_RtpAnalysisDialog.data,
    qt_meta_data_RtpAnalysisDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *RtpAnalysisDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RtpAnalysisDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_RtpAnalysisDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int RtpAnalysisDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 27)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 27;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 27)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 27;
    }
    return _id;
}

// SIGNAL 0
void RtpAnalysisDialog::goToPacket(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
