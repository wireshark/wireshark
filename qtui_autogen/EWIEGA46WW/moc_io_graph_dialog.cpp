/****************************************************************************
** Meta object code from reading C++ file 'io_graph_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/io_graph_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'io_graph_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_IOGraph_t {
    QByteArrayData data[13];
    char stringdata0[153];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_IOGraph_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_IOGraph_t qt_meta_stringdata_IOGraph = {
    {
QT_MOC_LITERAL(0, 0, 7), // "IOGraph"
QT_MOC_LITERAL(1, 8, 13), // "requestReplot"
QT_MOC_LITERAL(2, 22, 0), // ""
QT_MOC_LITERAL(3, 23, 13), // "requestRecalc"
QT_MOC_LITERAL(4, 37, 12), // "requestRetap"
QT_MOC_LITERAL(5, 50, 15), // "recalcGraphData"
QT_MOC_LITERAL(6, 66, 13), // "capture_file*"
QT_MOC_LITERAL(7, 80, 8), // "cap_file"
QT_MOC_LITERAL(8, 89, 14), // "enable_scaling"
QT_MOC_LITERAL(9, 104, 12), // "captureEvent"
QT_MOC_LITERAL(10, 117, 12), // "CaptureEvent"
QT_MOC_LITERAL(11, 130, 1), // "e"
QT_MOC_LITERAL(12, 132, 20) // "reloadValueUnitField"

    },
    "IOGraph\0requestReplot\0\0requestRecalc\0"
    "requestRetap\0recalcGraphData\0capture_file*\0"
    "cap_file\0enable_scaling\0captureEvent\0"
    "CaptureEvent\0e\0reloadValueUnitField"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_IOGraph[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   44,    2, 0x06 /* Public */,
       3,    0,   45,    2, 0x06 /* Public */,
       4,    0,   46,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       5,    2,   47,    2, 0x0a /* Public */,
       9,    1,   52,    2, 0x0a /* Public */,
      12,    0,   55,    2, 0x0a /* Public */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 6, QMetaType::Bool,    7,    8,
    QMetaType::Void, 0x80000000 | 10,   11,
    QMetaType::Void,

       0        // eod
};

void IOGraph::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        IOGraph *_t = static_cast<IOGraph *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->requestReplot(); break;
        case 1: _t->requestRecalc(); break;
        case 2: _t->requestRetap(); break;
        case 3: _t->recalcGraphData((*reinterpret_cast< capture_file*(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 4: _t->captureEvent((*reinterpret_cast< CaptureEvent(*)>(_a[1]))); break;
        case 5: _t->reloadValueUnitField(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (IOGraph::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraph::requestReplot)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (IOGraph::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraph::requestRecalc)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (IOGraph::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraph::requestRetap)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject IOGraph::staticMetaObject = { {
    &QObject::staticMetaObject,
    qt_meta_stringdata_IOGraph.data,
    qt_meta_data_IOGraph,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *IOGraph::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *IOGraph::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_IOGraph.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int IOGraph::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
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
void IOGraph::requestReplot()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void IOGraph::requestRecalc()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void IOGraph::requestRetap()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}
struct qt_meta_stringdata_IOGraphDialog_t {
    QByteArrayData data[67];
    char stringdata0[1316];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_IOGraphDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_IOGraphDialog_t qt_meta_stringdata_IOGraphDialog = {
    {
QT_MOC_LITERAL(0, 0, 13), // "IOGraphDialog"
QT_MOC_LITERAL(1, 14, 10), // "goToPacket"
QT_MOC_LITERAL(2, 25, 0), // ""
QT_MOC_LITERAL(3, 26, 10), // "packet_num"
QT_MOC_LITERAL(4, 37, 15), // "recalcGraphData"
QT_MOC_LITERAL(5, 53, 13), // "capture_file*"
QT_MOC_LITERAL(6, 67, 8), // "cap_file"
QT_MOC_LITERAL(7, 76, 14), // "enable_scaling"
QT_MOC_LITERAL(8, 91, 15), // "intervalChanged"
QT_MOC_LITERAL(9, 107, 8), // "interval"
QT_MOC_LITERAL(10, 116, 21), // "reloadValueUnitFields"
QT_MOC_LITERAL(11, 138, 14), // "scheduleReplot"
QT_MOC_LITERAL(12, 153, 3), // "now"
QT_MOC_LITERAL(13, 157, 14), // "scheduleRecalc"
QT_MOC_LITERAL(14, 172, 13), // "scheduleRetap"
QT_MOC_LITERAL(15, 186, 14), // "modelRowsReset"
QT_MOC_LITERAL(16, 201, 12), // "reloadFields"
QT_MOC_LITERAL(17, 214, 15), // "copyFromProfile"
QT_MOC_LITERAL(18, 230, 8), // "QAction*"
QT_MOC_LITERAL(19, 239, 6), // "action"
QT_MOC_LITERAL(20, 246, 13), // "updateWidgets"
QT_MOC_LITERAL(21, 260, 12), // "graphClicked"
QT_MOC_LITERAL(22, 273, 12), // "QMouseEvent*"
QT_MOC_LITERAL(23, 286, 5), // "event"
QT_MOC_LITERAL(24, 292, 10), // "mouseMoved"
QT_MOC_LITERAL(25, 303, 13), // "mouseReleased"
QT_MOC_LITERAL(26, 317, 9), // "resetAxes"
QT_MOC_LITERAL(27, 327, 16), // "updateStatistics"
QT_MOC_LITERAL(28, 344, 16), // "copyAsCsvClicked"
QT_MOC_LITERAL(29, 361, 39), // "on_intervalComboBox_currentIn..."
QT_MOC_LITERAL(30, 401, 5), // "index"
QT_MOC_LITERAL(31, 407, 22), // "on_todCheckBox_toggled"
QT_MOC_LITERAL(32, 430, 7), // "checked"
QT_MOC_LITERAL(33, 438, 16), // "modelDataChanged"
QT_MOC_LITERAL(34, 455, 11), // "QModelIndex"
QT_MOC_LITERAL(35, 467, 30), // "on_graphUat_currentItemChanged"
QT_MOC_LITERAL(36, 498, 7), // "current"
QT_MOC_LITERAL(37, 506, 8), // "previous"
QT_MOC_LITERAL(38, 515, 22), // "on_resetButton_clicked"
QT_MOC_LITERAL(39, 538, 22), // "on_logCheckBox_toggled"
QT_MOC_LITERAL(40, 561, 24), // "on_newToolButton_clicked"
QT_MOC_LITERAL(41, 586, 27), // "on_deleteToolButton_clicked"
QT_MOC_LITERAL(42, 614, 25), // "on_copyToolButton_clicked"
QT_MOC_LITERAL(43, 640, 26), // "on_clearToolButton_clicked"
QT_MOC_LITERAL(44, 667, 26), // "on_dragRadioButton_toggled"
QT_MOC_LITERAL(45, 694, 26), // "on_zoomRadioButton_toggled"
QT_MOC_LITERAL(46, 721, 24), // "on_actionReset_triggered"
QT_MOC_LITERAL(47, 746, 25), // "on_actionZoomIn_triggered"
QT_MOC_LITERAL(48, 772, 26), // "on_actionZoomInX_triggered"
QT_MOC_LITERAL(49, 799, 26), // "on_actionZoomInY_triggered"
QT_MOC_LITERAL(50, 826, 26), // "on_actionZoomOut_triggered"
QT_MOC_LITERAL(51, 853, 27), // "on_actionZoomOutX_triggered"
QT_MOC_LITERAL(52, 881, 27), // "on_actionZoomOutY_triggered"
QT_MOC_LITERAL(53, 909, 27), // "on_actionMoveUp10_triggered"
QT_MOC_LITERAL(54, 937, 29), // "on_actionMoveLeft10_triggered"
QT_MOC_LITERAL(55, 967, 30), // "on_actionMoveRight10_triggered"
QT_MOC_LITERAL(56, 998, 29), // "on_actionMoveDown10_triggered"
QT_MOC_LITERAL(57, 1028, 26), // "on_actionMoveUp1_triggered"
QT_MOC_LITERAL(58, 1055, 28), // "on_actionMoveLeft1_triggered"
QT_MOC_LITERAL(59, 1084, 29), // "on_actionMoveRight1_triggered"
QT_MOC_LITERAL(60, 1114, 28), // "on_actionMoveDown1_triggered"
QT_MOC_LITERAL(61, 1143, 29), // "on_actionGoToPacket_triggered"
QT_MOC_LITERAL(62, 1173, 27), // "on_actionDragZoom_triggered"
QT_MOC_LITERAL(63, 1201, 35), // "on_actionToggleTimeOrigin_tri..."
QT_MOC_LITERAL(64, 1237, 29), // "on_actionCrosshairs_triggered"
QT_MOC_LITERAL(65, 1267, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(66, 1294, 21) // "on_buttonBox_accepted"

    },
    "IOGraphDialog\0goToPacket\0\0packet_num\0"
    "recalcGraphData\0capture_file*\0cap_file\0"
    "enable_scaling\0intervalChanged\0interval\0"
    "reloadValueUnitFields\0scheduleReplot\0"
    "now\0scheduleRecalc\0scheduleRetap\0"
    "modelRowsReset\0reloadFields\0copyFromProfile\0"
    "QAction*\0action\0updateWidgets\0"
    "graphClicked\0QMouseEvent*\0event\0"
    "mouseMoved\0mouseReleased\0resetAxes\0"
    "updateStatistics\0copyAsCsvClicked\0"
    "on_intervalComboBox_currentIndexChanged\0"
    "index\0on_todCheckBox_toggled\0checked\0"
    "modelDataChanged\0QModelIndex\0"
    "on_graphUat_currentItemChanged\0current\0"
    "previous\0on_resetButton_clicked\0"
    "on_logCheckBox_toggled\0on_newToolButton_clicked\0"
    "on_deleteToolButton_clicked\0"
    "on_copyToolButton_clicked\0"
    "on_clearToolButton_clicked\0"
    "on_dragRadioButton_toggled\0"
    "on_zoomRadioButton_toggled\0"
    "on_actionReset_triggered\0"
    "on_actionZoomIn_triggered\0"
    "on_actionZoomInX_triggered\0"
    "on_actionZoomInY_triggered\0"
    "on_actionZoomOut_triggered\0"
    "on_actionZoomOutX_triggered\0"
    "on_actionZoomOutY_triggered\0"
    "on_actionMoveUp10_triggered\0"
    "on_actionMoveLeft10_triggered\0"
    "on_actionMoveRight10_triggered\0"
    "on_actionMoveDown10_triggered\0"
    "on_actionMoveUp1_triggered\0"
    "on_actionMoveLeft1_triggered\0"
    "on_actionMoveRight1_triggered\0"
    "on_actionMoveDown1_triggered\0"
    "on_actionGoToPacket_triggered\0"
    "on_actionDragZoom_triggered\0"
    "on_actionToggleTimeOrigin_triggered\0"
    "on_actionCrosshairs_triggered\0"
    "on_buttonBox_helpRequested\0"
    "on_buttonBox_accepted"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_IOGraphDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      53,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,  279,    2, 0x06 /* Public */,
       4,    2,  282,    2, 0x06 /* Public */,
       8,    1,  287,    2, 0x06 /* Public */,
      10,    0,  290,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      11,    1,  291,    2, 0x0a /* Public */,
      11,    0,  294,    2, 0x2a /* Public | MethodCloned */,
      13,    1,  295,    2, 0x0a /* Public */,
      13,    0,  298,    2, 0x2a /* Public | MethodCloned */,
      14,    1,  299,    2, 0x0a /* Public */,
      14,    0,  302,    2, 0x2a /* Public | MethodCloned */,
      15,    0,  303,    2, 0x0a /* Public */,
      16,    0,  304,    2, 0x0a /* Public */,
      17,    1,  305,    2, 0x08 /* Private */,
      20,    0,  308,    2, 0x08 /* Private */,
      21,    1,  309,    2, 0x08 /* Private */,
      24,    1,  312,    2, 0x08 /* Private */,
      25,    1,  315,    2, 0x08 /* Private */,
      26,    0,  318,    2, 0x08 /* Private */,
      27,    0,  319,    2, 0x08 /* Private */,
      28,    0,  320,    2, 0x08 /* Private */,
      29,    1,  321,    2, 0x08 /* Private */,
      31,    1,  324,    2, 0x08 /* Private */,
      33,    1,  327,    2, 0x08 /* Private */,
      35,    2,  330,    2, 0x08 /* Private */,
      38,    0,  335,    2, 0x08 /* Private */,
      39,    1,  336,    2, 0x08 /* Private */,
      40,    0,  339,    2, 0x08 /* Private */,
      41,    0,  340,    2, 0x08 /* Private */,
      42,    0,  341,    2, 0x08 /* Private */,
      43,    0,  342,    2, 0x08 /* Private */,
      44,    1,  343,    2, 0x08 /* Private */,
      45,    1,  346,    2, 0x08 /* Private */,
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

 // signals: parameters
    QMetaType::Void, QMetaType::Int,    3,
    QMetaType::Void, 0x80000000 | 5, QMetaType::Bool,    6,    7,
    QMetaType::Void, QMetaType::Int,    9,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool,   12,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   12,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   12,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 18,   19,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 22,   23,
    QMetaType::Void, 0x80000000 | 22,   23,
    QMetaType::Void, 0x80000000 | 22,   23,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   30,
    QMetaType::Void, QMetaType::Bool,   32,
    QMetaType::Void, 0x80000000 | 34,   30,
    QMetaType::Void, 0x80000000 | 34, 0x80000000 | 34,   36,   37,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   32,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   32,
    QMetaType::Void, QMetaType::Bool,   32,
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

void IOGraphDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        IOGraphDialog *_t = static_cast<IOGraphDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->goToPacket((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->recalcGraphData((*reinterpret_cast< capture_file*(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 2: _t->intervalChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->reloadValueUnitFields(); break;
        case 4: _t->scheduleReplot((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->scheduleReplot(); break;
        case 6: _t->scheduleRecalc((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->scheduleRecalc(); break;
        case 8: _t->scheduleRetap((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 9: _t->scheduleRetap(); break;
        case 10: _t->modelRowsReset(); break;
        case 11: _t->reloadFields(); break;
        case 12: _t->copyFromProfile((*reinterpret_cast< QAction*(*)>(_a[1]))); break;
        case 13: _t->updateWidgets(); break;
        case 14: _t->graphClicked((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 15: _t->mouseMoved((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 16: _t->mouseReleased((*reinterpret_cast< QMouseEvent*(*)>(_a[1]))); break;
        case 17: _t->resetAxes(); break;
        case 18: _t->updateStatistics(); break;
        case 19: _t->copyAsCsvClicked(); break;
        case 20: _t->on_intervalComboBox_currentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 21: _t->on_todCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 22: _t->modelDataChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1]))); break;
        case 23: _t->on_graphUat_currentItemChanged((*reinterpret_cast< const QModelIndex(*)>(_a[1])),(*reinterpret_cast< const QModelIndex(*)>(_a[2]))); break;
        case 24: _t->on_resetButton_clicked(); break;
        case 25: _t->on_logCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 26: _t->on_newToolButton_clicked(); break;
        case 27: _t->on_deleteToolButton_clicked(); break;
        case 28: _t->on_copyToolButton_clicked(); break;
        case 29: _t->on_clearToolButton_clicked(); break;
        case 30: _t->on_dragRadioButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 31: _t->on_zoomRadioButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 32: _t->on_actionReset_triggered(); break;
        case 33: _t->on_actionZoomIn_triggered(); break;
        case 34: _t->on_actionZoomInX_triggered(); break;
        case 35: _t->on_actionZoomInY_triggered(); break;
        case 36: _t->on_actionZoomOut_triggered(); break;
        case 37: _t->on_actionZoomOutX_triggered(); break;
        case 38: _t->on_actionZoomOutY_triggered(); break;
        case 39: _t->on_actionMoveUp10_triggered(); break;
        case 40: _t->on_actionMoveLeft10_triggered(); break;
        case 41: _t->on_actionMoveRight10_triggered(); break;
        case 42: _t->on_actionMoveDown10_triggered(); break;
        case 43: _t->on_actionMoveUp1_triggered(); break;
        case 44: _t->on_actionMoveLeft1_triggered(); break;
        case 45: _t->on_actionMoveRight1_triggered(); break;
        case 46: _t->on_actionMoveDown1_triggered(); break;
        case 47: _t->on_actionGoToPacket_triggered(); break;
        case 48: _t->on_actionDragZoom_triggered(); break;
        case 49: _t->on_actionToggleTimeOrigin_triggered(); break;
        case 50: _t->on_actionCrosshairs_triggered(); break;
        case 51: _t->on_buttonBox_helpRequested(); break;
        case 52: _t->on_buttonBox_accepted(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 12:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAction* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (IOGraphDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraphDialog::goToPacket)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (IOGraphDialog::*)(capture_file * , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraphDialog::recalcGraphData)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (IOGraphDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraphDialog::intervalChanged)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (IOGraphDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&IOGraphDialog::reloadValueUnitFields)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject IOGraphDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_IOGraphDialog.data,
    qt_meta_data_IOGraphDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *IOGraphDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *IOGraphDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_IOGraphDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int IOGraphDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
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
void IOGraphDialog::goToPacket(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void IOGraphDialog::recalcGraphData(capture_file * _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void IOGraphDialog::intervalChanged(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void IOGraphDialog::reloadValueUnitFields()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
