/****************************************************************************
** Meta object code from reading C++ file 'traffic_table_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/traffic_table_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'traffic_table_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_TrafficTableTreeWidget_t {
    QByteArrayData data[18];
    char stringdata0[240];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_TrafficTableTreeWidget_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_TrafficTableTreeWidget_t qt_meta_stringdata_TrafficTableTreeWidget = {
    {
QT_MOC_LITERAL(0, 0, 22), // "TrafficTableTreeWidget"
QT_MOC_LITERAL(1, 23, 12), // "titleChanged"
QT_MOC_LITERAL(2, 36, 0), // ""
QT_MOC_LITERAL(3, 37, 8), // "QWidget*"
QT_MOC_LITERAL(4, 46, 4), // "tree"
QT_MOC_LITERAL(5, 51, 4), // "text"
QT_MOC_LITERAL(6, 56, 12), // "filterAction"
QT_MOC_LITERAL(7, 69, 6), // "filter"
QT_MOC_LITERAL(8, 76, 20), // "FilterAction::Action"
QT_MOC_LITERAL(9, 97, 6), // "action"
QT_MOC_LITERAL(10, 104, 24), // "FilterAction::ActionType"
QT_MOC_LITERAL(11, 129, 4), // "type"
QT_MOC_LITERAL(12, 134, 24), // "setNameResolutionEnabled"
QT_MOC_LITERAL(13, 159, 6), // "enable"
QT_MOC_LITERAL(14, 166, 16), // "trafficTreeTitle"
QT_MOC_LITERAL(15, 183, 15), // "trafficTreeHash"
QT_MOC_LITERAL(16, 199, 12), // "conv_hash_t*"
QT_MOC_LITERAL(17, 212, 27) // "updateItemsForSettingChange"

    },
    "TrafficTableTreeWidget\0titleChanged\0"
    "\0QWidget*\0tree\0text\0filterAction\0"
    "filter\0FilterAction::Action\0action\0"
    "FilterAction::ActionType\0type\0"
    "setNameResolutionEnabled\0enable\0"
    "trafficTreeTitle\0trafficTreeHash\0"
    "conv_hash_t*\0updateItemsForSettingChange"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_TrafficTableTreeWidget[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       2,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   44,    2, 0x06 /* Public */,
       6,    3,   49,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      12,    1,   56,    2, 0x0a /* Public */,
      14,    0,   59,    2, 0x0a /* Public */,
      15,    0,   60,    2, 0x0a /* Public */,
      17,    0,   61,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, 0x80000000 | 3, QMetaType::QString,    4,    5,
    QMetaType::Void, QMetaType::QString, 0x80000000 | 8, 0x80000000 | 10,    7,    9,   11,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool,   13,
    QMetaType::Void,
    0x80000000 | 16,
    QMetaType::Void,

       0        // eod
};

void TrafficTableTreeWidget::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TrafficTableTreeWidget *_t = static_cast<TrafficTableTreeWidget *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->titleChanged((*reinterpret_cast< QWidget*(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 1: _t->filterAction((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< FilterAction::Action(*)>(_a[2])),(*reinterpret_cast< FilterAction::ActionType(*)>(_a[3]))); break;
        case 2: _t->setNameResolutionEnabled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->trafficTreeTitle(); break;
        case 4: { conv_hash_t* _r = _t->trafficTreeHash();
            if (_a[0]) *reinterpret_cast< conv_hash_t**>(_a[0]) = std::move(_r); }  break;
        case 5: _t->updateItemsForSettingChange(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 0:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QWidget* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TrafficTableTreeWidget::*)(QWidget * , const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TrafficTableTreeWidget::titleChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (TrafficTableTreeWidget::*)(QString , FilterAction::Action , FilterAction::ActionType );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TrafficTableTreeWidget::filterAction)) {
                *result = 1;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject TrafficTableTreeWidget::staticMetaObject = { {
    &QTreeWidget::staticMetaObject,
    qt_meta_stringdata_TrafficTableTreeWidget.data,
    qt_meta_data_TrafficTableTreeWidget,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *TrafficTableTreeWidget::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TrafficTableTreeWidget::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_TrafficTableTreeWidget.stringdata0))
        return static_cast<void*>(this);
    return QTreeWidget::qt_metacast(_clname);
}

int TrafficTableTreeWidget::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QTreeWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void TrafficTableTreeWidget::titleChanged(QWidget * _t1, const QString & _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void TrafficTableTreeWidget::filterAction(QString _t1, FilterAction::Action _t2, FilterAction::ActionType _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}
struct qt_meta_stringdata_TrafficTableDialog_t {
    QByteArrayData data[30];
    char stringdata0[432];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_TrafficTableDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_TrafficTableDialog_t qt_meta_stringdata_TrafficTableDialog = {
    {
QT_MOC_LITERAL(0, 0, 18), // "TrafficTableDialog"
QT_MOC_LITERAL(1, 19, 12), // "filterAction"
QT_MOC_LITERAL(2, 32, 0), // ""
QT_MOC_LITERAL(3, 33, 6), // "filter"
QT_MOC_LITERAL(4, 40, 20), // "FilterAction::Action"
QT_MOC_LITERAL(5, 61, 6), // "action"
QT_MOC_LITERAL(6, 68, 24), // "FilterAction::ActionType"
QT_MOC_LITERAL(7, 93, 4), // "type"
QT_MOC_LITERAL(8, 98, 22), // "openFollowStreamDialog"
QT_MOC_LITERAL(9, 121, 13), // "follow_type_t"
QT_MOC_LITERAL(10, 135, 18), // "openTcpStreamGraph"
QT_MOC_LITERAL(11, 154, 10), // "graph_type"
QT_MOC_LITERAL(12, 165, 17), // "currentTabChanged"
QT_MOC_LITERAL(13, 183, 13), // "updateWidgets"
QT_MOC_LITERAL(14, 197, 33), // "on_nameResolutionCheckBox_tog..."
QT_MOC_LITERAL(15, 231, 7), // "checked"
QT_MOC_LITERAL(16, 239, 32), // "on_displayFilterCheckBox_toggled"
QT_MOC_LITERAL(17, 272, 10), // "setTabText"
QT_MOC_LITERAL(18, 283, 8), // "QWidget*"
QT_MOC_LITERAL(19, 292, 4), // "tree"
QT_MOC_LITERAL(20, 297, 4), // "text"
QT_MOC_LITERAL(21, 302, 11), // "toggleTable"
QT_MOC_LITERAL(22, 314, 12), // "captureEvent"
QT_MOC_LITERAL(23, 327, 12), // "CaptureEvent"
QT_MOC_LITERAL(24, 340, 1), // "e"
QT_MOC_LITERAL(25, 342, 9), // "copyAsCsv"
QT_MOC_LITERAL(26, 352, 10), // "copyAsYaml"
QT_MOC_LITERAL(27, 363, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(28, 390, 19), // "absolute_start_time"
QT_MOC_LITERAL(29, 410, 21) // "nanosecond_timestamps"

    },
    "TrafficTableDialog\0filterAction\0\0"
    "filter\0FilterAction::Action\0action\0"
    "FilterAction::ActionType\0type\0"
    "openFollowStreamDialog\0follow_type_t\0"
    "openTcpStreamGraph\0graph_type\0"
    "currentTabChanged\0updateWidgets\0"
    "on_nameResolutionCheckBox_toggled\0"
    "checked\0on_displayFilterCheckBox_toggled\0"
    "setTabText\0QWidget*\0tree\0text\0toggleTable\0"
    "captureEvent\0CaptureEvent\0e\0copyAsCsv\0"
    "copyAsYaml\0on_buttonBox_helpRequested\0"
    "absolute_start_time\0nanosecond_timestamps"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_TrafficTableDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       2,  112, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    3,   79,    2, 0x06 /* Public */,
       8,    1,   86,    2, 0x06 /* Public */,
      10,    1,   89,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      12,    0,   92,    2, 0x09 /* Protected */,
      13,    0,   93,    2, 0x09 /* Protected */,
      14,    1,   94,    2, 0x08 /* Private */,
      16,    1,   97,    2, 0x08 /* Private */,
      17,    2,  100,    2, 0x08 /* Private */,
      21,    0,  105,    2, 0x08 /* Private */,
      22,    1,  106,    2, 0x08 /* Private */,
      25,    0,  109,    2, 0x08 /* Private */,
      26,    0,  110,    2, 0x08 /* Private */,
      27,    0,  111,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, 0x80000000 | 4, 0x80000000 | 6,    3,    5,    7,
    QMetaType::Void, 0x80000000 | 9,    7,
    QMetaType::Void, QMetaType::Int,   11,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   15,
    QMetaType::Void, QMetaType::Bool,   15,
    QMetaType::Void, 0x80000000 | 18, QMetaType::QString,   19,   20,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 23,   24,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

 // properties: name, type, flags
      28, QMetaType::Bool, 0x00095001,
      29, QMetaType::Bool, 0x00095001,

       0        // eod
};

void TrafficTableDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TrafficTableDialog *_t = static_cast<TrafficTableDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterAction((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< FilterAction::Action(*)>(_a[2])),(*reinterpret_cast< FilterAction::ActionType(*)>(_a[3]))); break;
        case 1: _t->openFollowStreamDialog((*reinterpret_cast< follow_type_t(*)>(_a[1]))); break;
        case 2: _t->openTcpStreamGraph((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->currentTabChanged(); break;
        case 4: _t->updateWidgets(); break;
        case 5: _t->on_nameResolutionCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->on_displayFilterCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 7: _t->setTabText((*reinterpret_cast< QWidget*(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 8: _t->toggleTable(); break;
        case 9: _t->captureEvent((*reinterpret_cast< CaptureEvent(*)>(_a[1]))); break;
        case 10: _t->copyAsCsv(); break;
        case 11: _t->copyAsYaml(); break;
        case 12: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 7:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QWidget* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TrafficTableDialog::*)(QString , FilterAction::Action , FilterAction::ActionType );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TrafficTableDialog::filterAction)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (TrafficTableDialog::*)(follow_type_t );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TrafficTableDialog::openFollowStreamDialog)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (TrafficTableDialog::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TrafficTableDialog::openTcpStreamGraph)) {
                *result = 2;
                return;
            }
        }
    }
#ifndef QT_NO_PROPERTIES
    else if (_c == QMetaObject::ReadProperty) {
        TrafficTableDialog *_t = static_cast<TrafficTableDialog *>(_o);
        Q_UNUSED(_t)
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< bool*>(_v) = _t->absoluteStartTime(); break;
        case 1: *reinterpret_cast< bool*>(_v) = _t->nanosecondTimestamps(); break;
        default: break;
        }
    } else if (_c == QMetaObject::WriteProperty) {
    } else if (_c == QMetaObject::ResetProperty) {
    }
#endif // QT_NO_PROPERTIES
}

QT_INIT_METAOBJECT const QMetaObject TrafficTableDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_TrafficTableDialog.data,
    qt_meta_data_TrafficTableDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *TrafficTableDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TrafficTableDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_TrafficTableDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int TrafficTableDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    }
#ifndef QT_NO_PROPERTIES
   else if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyDesignable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyScriptable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyStored) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyEditable) {
        _id -= 2;
    } else if (_c == QMetaObject::QueryPropertyUser) {
        _id -= 2;
    }
#endif // QT_NO_PROPERTIES
    return _id;
}

// SIGNAL 0
void TrafficTableDialog::filterAction(QString _t1, FilterAction::Action _t2, FilterAction::ActionType _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void TrafficTableDialog::openFollowStreamDialog(follow_type_t _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void TrafficTableDialog::openTcpStreamGraph(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
