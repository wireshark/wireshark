/****************************************************************************
** Meta object code from reading C++ file 'lte_rlc_statistics_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/lte_rlc_statistics_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'lte_rlc_statistics_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_LteRlcStatisticsDialog_t {
    QByteArrayData data[20];
    char stringdata0[283];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_LteRlcStatisticsDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_LteRlcStatisticsDialog_t qt_meta_stringdata_LteRlcStatisticsDialog = {
    {
QT_MOC_LITERAL(0, 0, 22), // "LteRlcStatisticsDialog"
QT_MOC_LITERAL(1, 23, 14), // "launchRLCGraph"
QT_MOC_LITERAL(2, 38, 0), // ""
QT_MOC_LITERAL(3, 39, 12), // "channelKnown"
QT_MOC_LITERAL(4, 52, 7), // "guint16"
QT_MOC_LITERAL(5, 60, 4), // "ueid"
QT_MOC_LITERAL(6, 65, 6), // "guint8"
QT_MOC_LITERAL(7, 72, 7), // "rlcMode"
QT_MOC_LITERAL(8, 80, 11), // "channelType"
QT_MOC_LITERAL(9, 92, 9), // "channelId"
QT_MOC_LITERAL(10, 102, 9), // "direction"
QT_MOC_LITERAL(11, 112, 8), // "fillTree"
QT_MOC_LITERAL(12, 121, 26), // "updateItemSelectionChanged"
QT_MOC_LITERAL(13, 148, 18), // "captureFileClosing"
QT_MOC_LITERAL(14, 167, 34), // "useRLCFramesFromMacCheckBoxTo..."
QT_MOC_LITERAL(15, 202, 5), // "state"
QT_MOC_LITERAL(16, 208, 26), // "launchULGraphButtonClicked"
QT_MOC_LITERAL(17, 235, 26), // "launchDLGraphButtonClicked"
QT_MOC_LITERAL(18, 262, 13), // "filterUpdated"
QT_MOC_LITERAL(19, 276, 6) // "filter"

    },
    "LteRlcStatisticsDialog\0launchRLCGraph\0"
    "\0channelKnown\0guint16\0ueid\0guint8\0"
    "rlcMode\0channelType\0channelId\0direction\0"
    "fillTree\0updateItemSelectionChanged\0"
    "captureFileClosing\0"
    "useRLCFramesFromMacCheckBoxToggled\0"
    "state\0launchULGraphButtonClicked\0"
    "launchDLGraphButtonClicked\0filterUpdated\0"
    "filter"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_LteRlcStatisticsDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    6,   54,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      11,    0,   67,    2, 0x08 /* Private */,
      12,    0,   68,    2, 0x08 /* Private */,
      13,    0,   69,    2, 0x08 /* Private */,
      14,    1,   70,    2, 0x08 /* Private */,
      16,    0,   73,    2, 0x08 /* Private */,
      17,    0,   74,    2, 0x08 /* Private */,
      18,    1,   75,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool, 0x80000000 | 4, 0x80000000 | 6, 0x80000000 | 4, 0x80000000 | 4, 0x80000000 | 6,    3,    5,    7,    8,    9,   10,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   15,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   19,

       0        // eod
};

void LteRlcStatisticsDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        LteRlcStatisticsDialog *_t = static_cast<LteRlcStatisticsDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->launchRLCGraph((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< guint16(*)>(_a[2])),(*reinterpret_cast< guint8(*)>(_a[3])),(*reinterpret_cast< guint16(*)>(_a[4])),(*reinterpret_cast< guint16(*)>(_a[5])),(*reinterpret_cast< guint8(*)>(_a[6]))); break;
        case 1: _t->fillTree(); break;
        case 2: _t->updateItemSelectionChanged(); break;
        case 3: _t->captureFileClosing(); break;
        case 4: _t->useRLCFramesFromMacCheckBoxToggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->launchULGraphButtonClicked(); break;
        case 6: _t->launchDLGraphButtonClicked(); break;
        case 7: _t->filterUpdated((*reinterpret_cast< QString(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (LteRlcStatisticsDialog::*)(bool , guint16 , guint8 , guint16 , guint16 , guint8 );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&LteRlcStatisticsDialog::launchRLCGraph)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject LteRlcStatisticsDialog::staticMetaObject = { {
    &TapParameterDialog::staticMetaObject,
    qt_meta_stringdata_LteRlcStatisticsDialog.data,
    qt_meta_data_LteRlcStatisticsDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *LteRlcStatisticsDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *LteRlcStatisticsDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_LteRlcStatisticsDialog.stringdata0))
        return static_cast<void*>(this);
    return TapParameterDialog::qt_metacast(_clname);
}

int LteRlcStatisticsDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = TapParameterDialog::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void LteRlcStatisticsDialog::launchRLCGraph(bool _t1, guint16 _t2, guint8 _t3, guint16 _t4, guint16 _t5, guint8 _t6)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)), const_cast<void*>(reinterpret_cast<const void*>(&_t3)), const_cast<void*>(reinterpret_cast<const void*>(&_t4)), const_cast<void*>(reinterpret_cast<const void*>(&_t5)), const_cast<void*>(reinterpret_cast<const void*>(&_t6)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
