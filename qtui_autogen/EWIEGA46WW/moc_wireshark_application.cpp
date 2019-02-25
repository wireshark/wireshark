/****************************************************************************
** Meta object code from reading C++ file 'wireshark_application.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/wireshark_application.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'wireshark_application.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_WiresharkApplication_t {
    QByteArrayData data[52];
    char stringdata0[812];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_WiresharkApplication_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_WiresharkApplication_t qt_meta_stringdata_WiresharkApplication = {
    {
QT_MOC_LITERAL(0, 0, 20), // "WiresharkApplication"
QT_MOC_LITERAL(1, 21, 14), // "appInitialized"
QT_MOC_LITERAL(2, 36, 0), // ""
QT_MOC_LITERAL(3, 37, 25), // "localInterfaceListChanged"
QT_MOC_LITERAL(4, 63, 15), // "openCaptureFile"
QT_MOC_LITERAL(5, 79, 7), // "cf_path"
QT_MOC_LITERAL(6, 87, 14), // "display_filter"
QT_MOC_LITERAL(7, 102, 4), // "type"
QT_MOC_LITERAL(8, 107, 18), // "openCaptureOptions"
QT_MOC_LITERAL(9, 126, 21), // "recentPreferencesRead"
QT_MOC_LITERAL(10, 148, 25), // "updateRecentCaptureStatus"
QT_MOC_LITERAL(11, 174, 8), // "filename"
QT_MOC_LITERAL(12, 183, 4), // "size"
QT_MOC_LITERAL(13, 188, 10), // "accessible"
QT_MOC_LITERAL(14, 199, 12), // "splashUpdate"
QT_MOC_LITERAL(15, 212, 17), // "register_action_e"
QT_MOC_LITERAL(16, 230, 6), // "action"
QT_MOC_LITERAL(17, 237, 11), // "const char*"
QT_MOC_LITERAL(18, 249, 7), // "message"
QT_MOC_LITERAL(19, 257, 15), // "profileChanging"
QT_MOC_LITERAL(20, 273, 18), // "profileNameChanged"
QT_MOC_LITERAL(21, 292, 12), // "const gchar*"
QT_MOC_LITERAL(22, 305, 12), // "profile_name"
QT_MOC_LITERAL(23, 318, 14), // "columnsChanged"
QT_MOC_LITERAL(24, 333, 24), // "captureFilterListChanged"
QT_MOC_LITERAL(25, 358, 24), // "displayFilterListChanged"
QT_MOC_LITERAL(26, 383, 24), // "filterExpressionsChanged"
QT_MOC_LITERAL(27, 408, 23), // "packetDissectionChanged"
QT_MOC_LITERAL(28, 432, 18), // "preferencesChanged"
QT_MOC_LITERAL(29, 451, 24), // "addressResolutionChanged"
QT_MOC_LITERAL(30, 476, 17), // "columnDataChanged"
QT_MOC_LITERAL(31, 494, 18), // "checkDisplayFilter"
QT_MOC_LITERAL(32, 513, 13), // "fieldsChanged"
QT_MOC_LITERAL(33, 527, 16), // "reloadLuaPlugins"
QT_MOC_LITERAL(34, 544, 21), // "openStatCommandDialog"
QT_MOC_LITERAL(35, 566, 9), // "menu_path"
QT_MOC_LITERAL(36, 576, 3), // "arg"
QT_MOC_LITERAL(37, 580, 8), // "userdata"
QT_MOC_LITERAL(38, 589, 22), // "openTapParameterDialog"
QT_MOC_LITERAL(39, 612, 7), // "cfg_str"
QT_MOC_LITERAL(40, 620, 13), // "captureActive"
QT_MOC_LITERAL(41, 634, 17), // "zoomMonospaceFont"
QT_MOC_LITERAL(42, 652, 4), // "font"
QT_MOC_LITERAL(43, 657, 19), // "clearRecentCaptures"
QT_MOC_LITERAL(44, 677, 21), // "refreshRecentCaptures"
QT_MOC_LITERAL(45, 699, 19), // "captureEventHandler"
QT_MOC_LITERAL(46, 719, 12), // "CaptureEvent"
QT_MOC_LITERAL(47, 732, 10), // "updateTaps"
QT_MOC_LITERAL(48, 743, 7), // "cleanup"
QT_MOC_LITERAL(49, 751, 23), // "ifChangeEventsAvailable"
QT_MOC_LITERAL(50, 775, 18), // "itemStatusFinished"
QT_MOC_LITERAL(51, 794, 17) // "refreshPacketData"

    },
    "WiresharkApplication\0appInitialized\0"
    "\0localInterfaceListChanged\0openCaptureFile\0"
    "cf_path\0display_filter\0type\0"
    "openCaptureOptions\0recentPreferencesRead\0"
    "updateRecentCaptureStatus\0filename\0"
    "size\0accessible\0splashUpdate\0"
    "register_action_e\0action\0const char*\0"
    "message\0profileChanging\0profileNameChanged\0"
    "const gchar*\0profile_name\0columnsChanged\0"
    "captureFilterListChanged\0"
    "displayFilterListChanged\0"
    "filterExpressionsChanged\0"
    "packetDissectionChanged\0preferencesChanged\0"
    "addressResolutionChanged\0columnDataChanged\0"
    "checkDisplayFilter\0fieldsChanged\0"
    "reloadLuaPlugins\0openStatCommandDialog\0"
    "menu_path\0arg\0userdata\0openTapParameterDialog\0"
    "cfg_str\0captureActive\0zoomMonospaceFont\0"
    "font\0clearRecentCaptures\0refreshRecentCaptures\0"
    "captureEventHandler\0CaptureEvent\0"
    "updateTaps\0cleanup\0ifChangeEventsAvailable\0"
    "itemStatusFinished\0refreshPacketData"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_WiresharkApplication[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      35,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
      24,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,  189,    2, 0x06 /* Public */,
       3,    0,  190,    2, 0x06 /* Public */,
       4,    3,  191,    2, 0x06 /* Public */,
       8,    0,  198,    2, 0x06 /* Public */,
       9,    0,  199,    2, 0x06 /* Public */,
      10,    3,  200,    2, 0x06 /* Public */,
      14,    2,  207,    2, 0x06 /* Public */,
      19,    0,  212,    2, 0x06 /* Public */,
      20,    1,  213,    2, 0x06 /* Public */,
      23,    0,  216,    2, 0x06 /* Public */,
      24,    0,  217,    2, 0x06 /* Public */,
      25,    0,  218,    2, 0x06 /* Public */,
      26,    0,  219,    2, 0x06 /* Public */,
      27,    0,  220,    2, 0x06 /* Public */,
      28,    0,  221,    2, 0x06 /* Public */,
      29,    0,  222,    2, 0x06 /* Public */,
      30,    0,  223,    2, 0x06 /* Public */,
      31,    0,  224,    2, 0x06 /* Public */,
      32,    0,  225,    2, 0x06 /* Public */,
      33,    0,  226,    2, 0x06 /* Public */,
      34,    3,  227,    2, 0x06 /* Public */,
      38,    3,  234,    2, 0x06 /* Public */,
      40,    1,  241,    2, 0x06 /* Public */,
      41,    1,  244,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      43,    0,  247,    2, 0x0a /* Public */,
      44,    0,  248,    2, 0x0a /* Public */,
      45,    1,  249,    2, 0x0a /* Public */,
      47,    0,  252,    2, 0x08 /* Private */,
      48,    0,  253,    2, 0x08 /* Private */,
      49,    0,  254,    2, 0x08 /* Private */,
      50,    3,  255,    2, 0x08 /* Private */,
      50,    2,  262,    2, 0x28 /* Private | MethodCloned */,
      50,    1,  267,    2, 0x28 /* Private | MethodCloned */,
      50,    0,  270,    2, 0x28 /* Private | MethodCloned */,
      51,    0,  271,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::UInt,    5,    6,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::LongLong, QMetaType::Bool,   11,   12,   13,
    QMetaType::Void, 0x80000000 | 15, 0x80000000 | 17,   16,   18,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 21,   22,
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
    QMetaType::Void, QMetaType::QString, 0x80000000 | 17, QMetaType::VoidStar,   35,   36,   37,
    QMetaType::Void, QMetaType::QString, QMetaType::QString, QMetaType::VoidStar,   39,   36,   37,
    QMetaType::Void, QMetaType::Int,    2,
    QMetaType::Void, QMetaType::QFont,   42,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 46,    2,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::LongLong, QMetaType::Bool,   11,   12,   13,
    QMetaType::Void, QMetaType::QString, QMetaType::LongLong,   11,   12,
    QMetaType::Void, QMetaType::QString,   11,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void WiresharkApplication::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        WiresharkApplication *_t = static_cast<WiresharkApplication *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->appInitialized(); break;
        case 1: _t->localInterfaceListChanged(); break;
        case 2: _t->openCaptureFile((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2])),(*reinterpret_cast< uint(*)>(_a[3]))); break;
        case 3: _t->openCaptureOptions(); break;
        case 4: _t->recentPreferencesRead(); break;
        case 5: _t->updateRecentCaptureStatus((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< qint64(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3]))); break;
        case 6: _t->splashUpdate((*reinterpret_cast< register_action_e(*)>(_a[1])),(*reinterpret_cast< const char*(*)>(_a[2]))); break;
        case 7: _t->profileChanging(); break;
        case 8: _t->profileNameChanged((*reinterpret_cast< const gchar*(*)>(_a[1]))); break;
        case 9: _t->columnsChanged(); break;
        case 10: _t->captureFilterListChanged(); break;
        case 11: _t->displayFilterListChanged(); break;
        case 12: _t->filterExpressionsChanged(); break;
        case 13: _t->packetDissectionChanged(); break;
        case 14: _t->preferencesChanged(); break;
        case 15: _t->addressResolutionChanged(); break;
        case 16: _t->columnDataChanged(); break;
        case 17: _t->checkDisplayFilter(); break;
        case 18: _t->fieldsChanged(); break;
        case 19: _t->reloadLuaPlugins(); break;
        case 20: _t->openStatCommandDialog((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const char*(*)>(_a[2])),(*reinterpret_cast< void*(*)>(_a[3]))); break;
        case 21: _t->openTapParameterDialog((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2])),(*reinterpret_cast< void*(*)>(_a[3]))); break;
        case 22: _t->captureActive((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 23: _t->zoomMonospaceFont((*reinterpret_cast< const QFont(*)>(_a[1]))); break;
        case 24: _t->clearRecentCaptures(); break;
        case 25: _t->refreshRecentCaptures(); break;
        case 26: _t->captureEventHandler((*reinterpret_cast< CaptureEvent(*)>(_a[1]))); break;
        case 27: _t->updateTaps(); break;
        case 28: _t->cleanup(); break;
        case 29: _t->ifChangeEventsAvailable(); break;
        case 30: _t->itemStatusFinished((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< qint64(*)>(_a[2])),(*reinterpret_cast< bool(*)>(_a[3]))); break;
        case 31: _t->itemStatusFinished((*reinterpret_cast< const QString(*)>(_a[1])),(*reinterpret_cast< qint64(*)>(_a[2]))); break;
        case 32: _t->itemStatusFinished((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 33: _t->itemStatusFinished(); break;
        case 34: _t->refreshPacketData(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::appInitialized)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::localInterfaceListChanged)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(QString , QString , unsigned int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::openCaptureFile)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::openCaptureOptions)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::recentPreferencesRead)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(const QString & , qint64 , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::updateRecentCaptureStatus)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(register_action_e , const char * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::splashUpdate)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::profileChanging)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(const gchar * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::profileNameChanged)) {
                *result = 8;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::columnsChanged)) {
                *result = 9;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::captureFilterListChanged)) {
                *result = 10;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::displayFilterListChanged)) {
                *result = 11;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::filterExpressionsChanged)) {
                *result = 12;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::packetDissectionChanged)) {
                *result = 13;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::preferencesChanged)) {
                *result = 14;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::addressResolutionChanged)) {
                *result = 15;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::columnDataChanged)) {
                *result = 16;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::checkDisplayFilter)) {
                *result = 17;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::fieldsChanged)) {
                *result = 18;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::reloadLuaPlugins)) {
                *result = 19;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(const QString & , const char * , void * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::openStatCommandDialog)) {
                *result = 20;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(const QString , const QString , void * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::openTapParameterDialog)) {
                *result = 21;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::captureActive)) {
                *result = 22;
                return;
            }
        }
        {
            using _t = void (WiresharkApplication::*)(const QFont & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&WiresharkApplication::zoomMonospaceFont)) {
                *result = 23;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject WiresharkApplication::staticMetaObject = { {
    &QApplication::staticMetaObject,
    qt_meta_stringdata_WiresharkApplication.data,
    qt_meta_data_WiresharkApplication,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *WiresharkApplication::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *WiresharkApplication::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_WiresharkApplication.stringdata0))
        return static_cast<void*>(this);
    return QApplication::qt_metacast(_clname);
}

int WiresharkApplication::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QApplication::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 35)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 35;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 35)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 35;
    }
    return _id;
}

// SIGNAL 0
void WiresharkApplication::appInitialized()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void WiresharkApplication::localInterfaceListChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void WiresharkApplication::openCaptureFile(QString _t1, QString _t2, unsigned int _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void WiresharkApplication::openCaptureOptions()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void WiresharkApplication::recentPreferencesRead()
{
    QMetaObject::activate(this, &staticMetaObject, 4, nullptr);
}

// SIGNAL 5
void WiresharkApplication::updateRecentCaptureStatus(const QString & _t1, qint64 _t2, bool _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 5, _a);
}

// SIGNAL 6
void WiresharkApplication::splashUpdate(register_action_e _t1, const char * _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 6, _a);
}

// SIGNAL 7
void WiresharkApplication::profileChanging()
{
    QMetaObject::activate(this, &staticMetaObject, 7, nullptr);
}

// SIGNAL 8
void WiresharkApplication::profileNameChanged(const gchar * _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}

// SIGNAL 9
void WiresharkApplication::columnsChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 9, nullptr);
}

// SIGNAL 10
void WiresharkApplication::captureFilterListChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 10, nullptr);
}

// SIGNAL 11
void WiresharkApplication::displayFilterListChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 11, nullptr);
}

// SIGNAL 12
void WiresharkApplication::filterExpressionsChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 12, nullptr);
}

// SIGNAL 13
void WiresharkApplication::packetDissectionChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 13, nullptr);
}

// SIGNAL 14
void WiresharkApplication::preferencesChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 14, nullptr);
}

// SIGNAL 15
void WiresharkApplication::addressResolutionChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 15, nullptr);
}

// SIGNAL 16
void WiresharkApplication::columnDataChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 16, nullptr);
}

// SIGNAL 17
void WiresharkApplication::checkDisplayFilter()
{
    QMetaObject::activate(this, &staticMetaObject, 17, nullptr);
}

// SIGNAL 18
void WiresharkApplication::fieldsChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 18, nullptr);
}

// SIGNAL 19
void WiresharkApplication::reloadLuaPlugins()
{
    QMetaObject::activate(this, &staticMetaObject, 19, nullptr);
}

// SIGNAL 20
void WiresharkApplication::openStatCommandDialog(const QString & _t1, const char * _t2, void * _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 20, _a);
}

// SIGNAL 21
void WiresharkApplication::openTapParameterDialog(const QString _t1, const QString _t2, void * _t3)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)) };
    QMetaObject::activate(this, &staticMetaObject, 21, _a);
}

// SIGNAL 22
void WiresharkApplication::captureActive(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 22, _a);
}

// SIGNAL 23
void WiresharkApplication::zoomMonospaceFont(const QFont & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 23, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
