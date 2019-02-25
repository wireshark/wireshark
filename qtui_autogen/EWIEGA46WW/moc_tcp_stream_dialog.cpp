/****************************************************************************
** Meta object code from reading C++ file 'tcp_stream_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/tcp_stream_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'tcp_stream_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_TCPStreamDialog_t {
    QByteArrayData data[71];
    char stringdata0[1685];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_TCPStreamDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_TCPStreamDialog_t qt_meta_stringdata_TCPStreamDialog = {
    {
QT_MOC_LITERAL(0, 0, 15), // "TCPStreamDialog"
QT_MOC_LITERAL(1, 16, 10), // "goToPacket"
QT_MOC_LITERAL(2, 27, 0), // ""
QT_MOC_LITERAL(3, 28, 10), // "packet_num"
QT_MOC_LITERAL(4, 39, 14), // "setCaptureFile"
QT_MOC_LITERAL(5, 54, 13), // "capture_file*"
QT_MOC_LITERAL(6, 68, 2), // "cf"
QT_MOC_LITERAL(7, 71, 11), // "updateGraph"
QT_MOC_LITERAL(8, 83, 12), // "graphClicked"
QT_MOC_LITERAL(9, 96, 12), // "QMouseEvent*"
QT_MOC_LITERAL(10, 109, 5), // "event"
QT_MOC_LITERAL(11, 115, 11), // "axisClicked"
QT_MOC_LITERAL(12, 127, 8), // "QCPAxis*"
QT_MOC_LITERAL(13, 136, 4), // "axis"
QT_MOC_LITERAL(14, 141, 23), // "QCPAxis::SelectablePart"
QT_MOC_LITERAL(15, 165, 4), // "part"
QT_MOC_LITERAL(16, 170, 10), // "mouseMoved"
QT_MOC_LITERAL(17, 181, 13), // "mouseReleased"
QT_MOC_LITERAL(18, 195, 15), // "transformYRange"
QT_MOC_LITERAL(19, 211, 8), // "QCPRange"
QT_MOC_LITERAL(20, 220, 8), // "y_range1"
QT_MOC_LITERAL(21, 229, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(22, 251, 40), // "on_graphTypeComboBox_currentI..."
QT_MOC_LITERAL(23, 292, 5), // "index"
QT_MOC_LITERAL(24, 298, 22), // "on_resetButton_clicked"
QT_MOC_LITERAL(25, 321, 35), // "on_streamNumberSpinBox_valueC..."
QT_MOC_LITERAL(26, 357, 10), // "new_stream"
QT_MOC_LITERAL(27, 368, 38), // "on_streamNumberSpinBox_editin..."
QT_MOC_LITERAL(28, 407, 35), // "on_maWindowSizeSpinBox_valueC..."
QT_MOC_LITERAL(29, 443, 11), // "new_ma_size"
QT_MOC_LITERAL(30, 455, 38), // "on_maWindowSizeSpinBox_editin..."
QT_MOC_LITERAL(31, 494, 35), // "on_selectSACKsCheckBox_stateC..."
QT_MOC_LITERAL(32, 530, 5), // "state"
QT_MOC_LITERAL(33, 536, 31), // "on_otherDirectionButton_clicked"
QT_MOC_LITERAL(34, 568, 26), // "on_dragRadioButton_toggled"
QT_MOC_LITERAL(35, 595, 7), // "checked"
QT_MOC_LITERAL(36, 603, 26), // "on_zoomRadioButton_toggled"
QT_MOC_LITERAL(37, 630, 35), // "on_bySeqNumberCheckBox_stateC..."
QT_MOC_LITERAL(38, 666, 37), // "on_showSegLengthCheckBox_stat..."
QT_MOC_LITERAL(39, 704, 38), // "on_showThroughputCheckBox_sta..."
QT_MOC_LITERAL(40, 743, 35), // "on_showGoodputCheckBox_stateC..."
QT_MOC_LITERAL(41, 779, 34), // "on_showRcvWinCheckBox_stateCh..."
QT_MOC_LITERAL(42, 814, 36), // "on_showBytesOutCheckBox_state..."
QT_MOC_LITERAL(43, 851, 25), // "on_actionZoomIn_triggered"
QT_MOC_LITERAL(44, 877, 26), // "on_actionZoomInX_triggered"
QT_MOC_LITERAL(45, 904, 26), // "on_actionZoomInY_triggered"
QT_MOC_LITERAL(46, 931, 26), // "on_actionZoomOut_triggered"
QT_MOC_LITERAL(47, 958, 27), // "on_actionZoomOutX_triggered"
QT_MOC_LITERAL(48, 986, 27), // "on_actionZoomOutY_triggered"
QT_MOC_LITERAL(49, 1014, 24), // "on_actionReset_triggered"
QT_MOC_LITERAL(50, 1039, 30), // "on_actionMoveRight10_triggered"
QT_MOC_LITERAL(51, 1070, 29), // "on_actionMoveLeft10_triggered"
QT_MOC_LITERAL(52, 1100, 27), // "on_actionMoveUp10_triggered"
QT_MOC_LITERAL(53, 1128, 29), // "on_actionMoveDown10_triggered"
QT_MOC_LITERAL(54, 1158, 29), // "on_actionMoveRight1_triggered"
QT_MOC_LITERAL(55, 1188, 28), // "on_actionMoveLeft1_triggered"
QT_MOC_LITERAL(56, 1217, 26), // "on_actionMoveUp1_triggered"
QT_MOC_LITERAL(57, 1244, 28), // "on_actionMoveDown1_triggered"
QT_MOC_LITERAL(58, 1273, 29), // "on_actionNextStream_triggered"
QT_MOC_LITERAL(59, 1303, 33), // "on_actionPreviousStream_trigg..."
QT_MOC_LITERAL(60, 1337, 34), // "on_actionSwitchDirection_trig..."
QT_MOC_LITERAL(61, 1372, 29), // "on_actionGoToPacket_triggered"
QT_MOC_LITERAL(62, 1402, 27), // "on_actionDragZoom_triggered"
QT_MOC_LITERAL(63, 1430, 40), // "on_actionToggleSequenceNumber..."
QT_MOC_LITERAL(64, 1471, 35), // "on_actionToggleTimeOrigin_tri..."
QT_MOC_LITERAL(65, 1507, 32), // "on_actionRoundTripTime_triggered"
QT_MOC_LITERAL(66, 1540, 29), // "on_actionThroughput_triggered"
QT_MOC_LITERAL(67, 1570, 26), // "on_actionStevens_triggered"
QT_MOC_LITERAL(68, 1597, 27), // "on_actionTcptrace_triggered"
QT_MOC_LITERAL(69, 1625, 32), // "on_actionWindowScaling_triggered"
QT_MOC_LITERAL(70, 1658, 26) // "on_buttonBox_helpRequested"

    },
    "TCPStreamDialog\0goToPacket\0\0packet_num\0"
    "setCaptureFile\0capture_file*\0cf\0"
    "updateGraph\0graphClicked\0QMouseEvent*\0"
    "event\0axisClicked\0QCPAxis*\0axis\0"
    "QCPAxis::SelectablePart\0part\0mouseMoved\0"
    "mouseReleased\0transformYRange\0QCPRange\0"
    "y_range1\0on_buttonBox_accepted\0"
    "on_graphTypeComboBox_currentIndexChanged\0"
    "index\0on_resetButton_clicked\0"
    "on_streamNumberSpinBox_valueChanged\0"
    "new_stream\0on_streamNumberSpinBox_editingFinished\0"
    "on_maWindowSizeSpinBox_valueChanged\0"
    "new_ma_size\0on_maWindowSizeSpinBox_editingFinished\0"
    "on_selectSACKsCheckBox_stateChanged\0"
    "state\0on_otherDirectionButton_clicked\0"
    "on_dragRadioButton_toggled\0checked\0"
    "on_zoomRadioButton_toggled\0"
    "on_bySeqNumberCheckBox_stateChanged\0"
    "on_showSegLengthCheckBox_stateChanged\0"
    "on_showThroughputCheckBox_stateChanged\0"
    "on_showGoodputCheckBox_stateChanged\0"
    "on_showRcvWinCheckBox_stateChanged\0"
    "on_showBytesOutCheckBox_stateChanged\0"
    "on_actionZoomIn_triggered\0"
    "on_actionZoomInX_triggered\0"
    "on_actionZoomInY_triggered\0"
    "on_actionZoomOut_triggered\0"
    "on_actionZoomOutX_triggered\0"
    "on_actionZoomOutY_triggered\0"
    "on_actionReset_triggered\0"
    "on_actionMoveRight10_triggered\0"
    "on_actionMoveLeft10_triggered\0"
    "on_actionMoveUp10_triggered\0"
    "on_actionMoveDown10_triggered\0"
    "on_actionMoveRight1_triggered\0"
    "on_actionMoveLeft1_triggered\0"
    "on_actionMoveUp1_triggered\0"
    "on_actionMoveDown1_triggered\0"
    "on_actionNextStream_triggered\0"
    "on_actionPreviousStream_triggered\0"
    "on_actionSwitchDirection_triggered\0"
    "on_actionGoToPacket_triggered\0"
    "on_actionDragZoom_triggered\0"
    "on_actionToggleSequenceNumbers_triggered\0"
    "on_actionToggleTimeOrigin_triggered\0"
    "on_actionRoundTripTime_triggered\0"
    "on_actionThroughput_triggered\0"
    "on_actionStevens_triggered\0"
    "on_actionTcptrace_triggered\0"
    "on_actionWindowScaling_triggered\0"
    "on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_TCPStreamDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      53,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,  279,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    1,  282,    2, 0x0a /* Public */,
       7,    0,  285,    2, 0x0a /* Public */,
       8,    1,  286,    2, 0x08 /* Private */,
      11,    3,  289,    2, 0x08 /* Private */,
      16,    1,  296,    2, 0x08 /* Private */,
      17,    1,  299,    2, 0x08 /* Private */,
      18,    1,  302,    2, 0x08 /* Private */,
      21,    0,  305,    2, 0x08 /* Private */,
      22,    1,  306,    2, 0x08 /* Private */,
      24,    0,  309,    2, 0x08 /* Private */,
      25,    1,  310,    2, 0x08 /* Private */,
      27,    0,  313,    2, 0x08 /* Private */,
      28,    1,  314,    2, 0x08 /* Private */,
      30,    0,  317,    2, 0x08 /* Private */,
      31,    1,  318,    2, 0x08 /* Private */,
      33,    0,  321,    2, 0x08 /* Private */,
      34,    1,  322,    2, 0x08 /* Private */,
      36,    1,  325,    2, 0x08 /* Private */,
      37,    1,  328,    2, 0x08 /* Private */,
      38,    1,  331,    2, 0x08 /* Private */,
      39,    1,  334,    2, 0x08 /* Private */,
      40,    1,  337,    2, 0x08 /* Private */,
      41,    1,  340,    2, 0x08 /* Private */,
      42,    1,  343,    2, 0x08 /* Private */,
      43,    0,  346,    2, 0x08 /* Private */,
      44,    0,  347,    2, 0x08 /* Private */,
      45,    0,  348,    2, 0x08 /* Private */,
      46,    0,  349,    2, 0x08 /* Private */,
      47,    0,  350,    2, 0x08 /* Private */,
      48,    0,  351,    2, 0x08 /* Private */,
      49,    0,  352,    2, 0x08 /* Private */,
      50,    0,  353,    2, 0x08 /* Private */,
      51,    0,  354,    2, 0x08 /* Private */,
      52,    0,  355,    2, 0x08 /* Private */,
      53,    0,  356,    2, 0x08 /* Private */,
      54,    0,  357,    2, 0x08 /* Private */,
      55,    0,  358,    2, 0x08 /* Private */,
      56,    0,  359,    2, 0x08 /* Private */,
      57,    0,  360,    2, 0x08 /* Private */,
      58,    0,  361,    2, 0x08 /* Private */,
      59,    0,  362,    2, 0x08 /* Private */,
      60,    0,  363,    2, 0x08 /* Private */,
      61,    0,  364,    2, 0x08 /* Private */,
      62,    0,  365,    2, 0x08 /* Private */,
      63,    0,  366,    2, 0x08 /* Private */,
      64,    0,  367,    2, 0x08 /* Private */,
      65,    0,  368,    2, 0x08 /* Private */,
      66,    0,  369,    2, 0x08 /* Private */,
      67,    0,  370,    2, 0x08 /* Private */,
      68,    0,  371,    2, 0x08 /* Private */,
      69,    0,  372,    2, 0x08 /* Private */,
      70,    0,  373,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 5,    6,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void, 0x80000000 | 12, 0x80000000 | 14, 0x80000000 | 9,   13,   15,   10,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void, 0x80000000 | 9,   10,
    QMetaType::Void, 0x80000000 | 19,   20,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   23,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   26,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Double,   29,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   35,
    QMetaType::Void, QMetaType::Bool,   35,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void, QMetaType::Int,   32,
    QMetaType::Void, QMetaType::Int,   32,
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
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void TCPStreamDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TCPStreamDialog *_t = static_cast<TCPStreamDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->goToPacket((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 2: _t->updateGraph(); break;
        case 3: _t->graphClicked((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 4: _t->axisClicked((*reinterpret_cast< QCPAxis*(*)>(_a[1])),(*reinterpret_cast< QCPAxis::SelectablePart(*)>(_a[2])),(*reinterpret_cast< QMouseEvent*(*)>(_a[3]))); break;
        case 5: _t->mouseMoved((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 6: _t->mouseReleased((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 7: _t->transformYRange((*reinterpret_cast< const QCPRange(*)>(_a[1]))); break;
        case 8: _t->on_buttonBox_accepted(); break;
        case 9: _t->on_graphTypeComboBox_currentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 10: _t->on_resetButton_clicked(); break;
        case 11: _t->on_streamNumberSpinBox_valueChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 12: _t->on_streamNumberSpinBox_editingFinished(); break;
        case 13: _t->on_maWindowSizeSpinBox_valueChanged((*reinterpret_cast< double(*)>(_a[1]))); break;
        case 14: _t->on_maWindowSizeSpinBox_editingFinished(); break;
        case 15: _t->on_selectSACKsCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 16: _t->on_otherDirectionButton_clicked(); break;
        case 17: _t->on_dragRadioButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 18: _t->on_zoomRadioButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 19: _t->on_bySeqNumberCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 20: _t->on_showSegLengthCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 21: _t->on_showThroughputCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 22: _t->on_showGoodputCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 23: _t->on_showRcvWinCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 24: _t->on_showBytesOutCheckBox_stateChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 25: _t->on_actionZoomIn_triggered(); break;
        case 26: _t->on_actionZoomInX_triggered(); break;
        case 27: _t->on_actionZoomInY_triggered(); break;
        case 28: _t->on_actionZoomOut_triggered(); break;
        case 29: _t->on_actionZoomOutX_triggered(); break;
        case 30: _t->on_actionZoomOutY_triggered(); break;
        case 31: _t->on_actionReset_triggered(); break;
        case 32: _t->on_actionMoveRight10_triggered(); break;
        case 33: _t->on_actionMoveLeft10_triggered(); break;
        case 34: _t->on_actionMoveUp10_triggered(); break;
        case 35: _t->on_actionMoveDown10_triggered(); break;
        case 36: _t->on_actionMoveRight1_triggered(); break;
        case 37: _t->on_actionMoveLeft1_triggered(); break;
        case 38: _t->on_actionMoveUp1_triggered(); break;
        case 39: _t->on_actionMoveDown1_triggered(); break;
        case 40: _t->on_actionNextStream_triggered(); break;
        case 41: _t->on_actionPreviousStream_triggered(); break;
        case 42: _t->on_actionSwitchDirection_triggered(); break;
        case 43: _t->on_actionGoToPacket_triggered(); break;
        case 44: _t->on_actionDragZoom_triggered(); break;
        case 45: _t->on_actionToggleSequenceNumbers_triggered(); break;
        case 46: _t->on_actionToggleTimeOrigin_triggered(); break;
        case 47: _t->on_actionRoundTripTime_triggered(); break;
        case 48: _t->on_actionThroughput_triggered(); break;
        case 49: _t->on_actionStevens_triggered(); break;
        case 50: _t->on_actionTcptrace_triggered(); break;
        case 51: _t->on_actionWindowScaling_triggered(); break;
        case 52: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 4:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QCPAxis* >(); break;
            case 1:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QCPAxis::SelectablePart >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TCPStreamDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TCPStreamDialog::goToPacket)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject TCPStreamDialog::staticMetaObject = { {
    &GeometryStateDialog::staticMetaObject,
    qt_meta_stringdata_TCPStreamDialog.data,
    qt_meta_data_TCPStreamDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *TCPStreamDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TCPStreamDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_TCPStreamDialog.stringdata0))
        return static_cast<void*>(this);
    return GeometryStateDialog::qt_metacast(_clname);
}

int TCPStreamDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = GeometryStateDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 53)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 53;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 53)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 53;
    }
    return _id;
}

// SIGNAL 0
void TCPStreamDialog::goToPacket(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
