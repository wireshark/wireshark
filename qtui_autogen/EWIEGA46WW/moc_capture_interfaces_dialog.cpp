/****************************************************************************
** Meta object code from reading C++ file 'capture_interfaces_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/capture_interfaces_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_interfaces_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_InterfaceTreeDelegate_t {
    QByteArrayData data[9];
    char stringdata0[125];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_InterfaceTreeDelegate_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_InterfaceTreeDelegate_t qt_meta_stringdata_InterfaceTreeDelegate = {
    {
QT_MOC_LITERAL(0, 0, 21), // "InterfaceTreeDelegate"
QT_MOC_LITERAL(1, 22, 13), // "filterChanged"
QT_MOC_LITERAL(2, 36, 0), // ""
QT_MOC_LITERAL(3, 37, 6), // "filter"
QT_MOC_LITERAL(4, 44, 15), // "linkTypeChanged"
QT_MOC_LITERAL(5, 60, 18), // "selected_link_type"
QT_MOC_LITERAL(6, 79, 21), // "snapshotLengthChanged"
QT_MOC_LITERAL(7, 101, 5), // "value"
QT_MOC_LITERAL(8, 107, 17) // "bufferSizeChanged"

    },
    "InterfaceTreeDelegate\0filterChanged\0"
    "\0filter\0linkTypeChanged\0selected_link_type\0"
    "snapshotLengthChanged\0value\0"
    "bufferSizeChanged"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_InterfaceTreeDelegate[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   34,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    1,   37,    2, 0x08 /* Private */,
       6,    1,   40,    2, 0x08 /* Private */,
       8,    1,   43,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void, QMetaType::Int,    7,
    QMetaType::Void, QMetaType::Int,    7,

       0        // eod
};

void InterfaceTreeDelegate::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        InterfaceTreeDelegate *_t = static_cast<InterfaceTreeDelegate *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->linkTypeChanged((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 2: _t->snapshotLengthChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->bufferSizeChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (InterfaceTreeDelegate::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&InterfaceTreeDelegate::filterChanged)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject InterfaceTreeDelegate::staticMetaObject = { {
    &QStyledItemDelegate::staticMetaObject,
    qt_meta_stringdata_InterfaceTreeDelegate.data,
    qt_meta_data_InterfaceTreeDelegate,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *InterfaceTreeDelegate::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *InterfaceTreeDelegate::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_InterfaceTreeDelegate.stringdata0))
        return static_cast<void*>(this);
    return QStyledItemDelegate::qt_metacast(_clname);
}

int InterfaceTreeDelegate::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QStyledItemDelegate::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 4)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 4;
    }
    return _id;
}

// SIGNAL 0
void InterfaceTreeDelegate::filterChanged(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
struct qt_meta_stringdata_CaptureInterfacesDialog_t {
    QByteArrayData data[46];
    char stringdata0[815];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureInterfacesDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureInterfacesDialog_t qt_meta_stringdata_CaptureInterfacesDialog = {
    {
QT_MOC_LITERAL(0, 0, 23), // "CaptureInterfacesDialog"
QT_MOC_LITERAL(1, 24, 12), // "startCapture"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 11), // "stopCapture"
QT_MOC_LITERAL(4, 50, 9), // "getPoints"
QT_MOC_LITERAL(5, 60, 3), // "row"
QT_MOC_LITERAL(6, 64, 10), // "PointList*"
QT_MOC_LITERAL(7, 75, 3), // "pts"
QT_MOC_LITERAL(8, 79, 21), // "setSelectedInterfaces"
QT_MOC_LITERAL(9, 101, 14), // "setFilterValid"
QT_MOC_LITERAL(10, 116, 5), // "valid"
QT_MOC_LITERAL(11, 122, 14), // "capture_filter"
QT_MOC_LITERAL(12, 137, 17), // "interfacesChanged"
QT_MOC_LITERAL(13, 155, 10), // "ifsChanged"
QT_MOC_LITERAL(14, 166, 20), // "interfaceListChanged"
QT_MOC_LITERAL(15, 187, 23), // "captureFilterTextEdited"
QT_MOC_LITERAL(16, 211, 4), // "text"
QT_MOC_LITERAL(17, 216, 34), // "on_capturePromModeCheckBox_to..."
QT_MOC_LITERAL(18, 251, 7), // "checked"
QT_MOC_LITERAL(19, 259, 28), // "on_gbStopCaptureAuto_toggled"
QT_MOC_LITERAL(20, 288, 28), // "on_cbUpdatePacketsRT_toggled"
QT_MOC_LITERAL(21, 317, 23), // "on_cbAutoScroll_toggled"
QT_MOC_LITERAL(22, 341, 24), // "on_gbNewFileAuto_toggled"
QT_MOC_LITERAL(23, 366, 29), // "on_cbExtraCaptureInfo_toggled"
QT_MOC_LITERAL(24, 396, 32), // "on_cbResolveMacAddresses_toggled"
QT_MOC_LITERAL(25, 429, 21), // "on_compileBPF_clicked"
QT_MOC_LITERAL(26, 451, 23), // "on_manageButton_clicked"
QT_MOC_LITERAL(27, 475, 32), // "on_cbResolveNetworkNames_toggled"
QT_MOC_LITERAL(28, 508, 34), // "on_cbResolveTransportNames_to..."
QT_MOC_LITERAL(29, 543, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(30, 565, 21), // "on_buttonBox_rejected"
QT_MOC_LITERAL(31, 587, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(32, 614, 17), // "interfaceSelected"
QT_MOC_LITERAL(33, 632, 12), // "filterEdited"
QT_MOC_LITERAL(34, 645, 13), // "updateWidgets"
QT_MOC_LITERAL(35, 659, 16), // "updateStatistics"
QT_MOC_LITERAL(36, 676, 20), // "refreshInterfaceList"
QT_MOC_LITERAL(37, 697, 21), // "updateLocalInterfaces"
QT_MOC_LITERAL(38, 719, 19), // "browseButtonClicked"
QT_MOC_LITERAL(39, 739, 20), // "interfaceItemChanged"
QT_MOC_LITERAL(40, 760, 16), // "QTreeWidgetItem*"
QT_MOC_LITERAL(41, 777, 4), // "item"
QT_MOC_LITERAL(42, 782, 6), // "column"
QT_MOC_LITERAL(43, 789, 11), // "changeEvent"
QT_MOC_LITERAL(44, 801, 7), // "QEvent*"
QT_MOC_LITERAL(45, 809, 5) // "event"

    },
    "CaptureInterfacesDialog\0startCapture\0"
    "\0stopCapture\0getPoints\0row\0PointList*\0"
    "pts\0setSelectedInterfaces\0setFilterValid\0"
    "valid\0capture_filter\0interfacesChanged\0"
    "ifsChanged\0interfaceListChanged\0"
    "captureFilterTextEdited\0text\0"
    "on_capturePromModeCheckBox_toggled\0"
    "checked\0on_gbStopCaptureAuto_toggled\0"
    "on_cbUpdatePacketsRT_toggled\0"
    "on_cbAutoScroll_toggled\0"
    "on_gbNewFileAuto_toggled\0"
    "on_cbExtraCaptureInfo_toggled\0"
    "on_cbResolveMacAddresses_toggled\0"
    "on_compileBPF_clicked\0on_manageButton_clicked\0"
    "on_cbResolveNetworkNames_toggled\0"
    "on_cbResolveTransportNames_toggled\0"
    "on_buttonBox_accepted\0on_buttonBox_rejected\0"
    "on_buttonBox_helpRequested\0interfaceSelected\0"
    "filterEdited\0updateWidgets\0updateStatistics\0"
    "refreshInterfaceList\0updateLocalInterfaces\0"
    "browseButtonClicked\0interfaceItemChanged\0"
    "QTreeWidgetItem*\0item\0column\0changeEvent\0"
    "QEvent*\0event"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureInterfacesDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      32,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       9,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,  174,    2, 0x06 /* Public */,
       3,    0,  175,    2, 0x06 /* Public */,
       4,    2,  176,    2, 0x06 /* Public */,
       8,    0,  181,    2, 0x06 /* Public */,
       9,    2,  182,    2, 0x06 /* Public */,
      12,    0,  187,    2, 0x06 /* Public */,
      13,    0,  188,    2, 0x06 /* Public */,
      14,    0,  189,    2, 0x06 /* Public */,
      15,    1,  190,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
      17,    1,  193,    2, 0x08 /* Private */,
      19,    1,  196,    2, 0x08 /* Private */,
      20,    1,  199,    2, 0x08 /* Private */,
      21,    1,  202,    2, 0x08 /* Private */,
      22,    1,  205,    2, 0x08 /* Private */,
      23,    1,  208,    2, 0x08 /* Private */,
      24,    1,  211,    2, 0x08 /* Private */,
      25,    0,  214,    2, 0x08 /* Private */,
      26,    0,  215,    2, 0x08 /* Private */,
      27,    1,  216,    2, 0x08 /* Private */,
      28,    1,  219,    2, 0x08 /* Private */,
      29,    0,  222,    2, 0x08 /* Private */,
      30,    0,  223,    2, 0x08 /* Private */,
      31,    0,  224,    2, 0x08 /* Private */,
      32,    0,  225,    2, 0x08 /* Private */,
      33,    0,  226,    2, 0x08 /* Private */,
      34,    0,  227,    2, 0x08 /* Private */,
      35,    0,  228,    2, 0x08 /* Private */,
      36,    0,  229,    2, 0x08 /* Private */,
      37,    0,  230,    2, 0x08 /* Private */,
      38,    0,  231,    2, 0x08 /* Private */,
      39,    2,  232,    2, 0x08 /* Private */,
      43,    1,  237,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, 0x80000000 | 6,    5,    7,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,   10,   11,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   16,

 // slots: parameters
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void, QMetaType::Bool,   18,
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
    QMetaType::Void, 0x80000000 | 40, QMetaType::Int,   41,   42,
    QMetaType::Void, 0x80000000 | 44,   45,

       0        // eod
};

void CaptureInterfacesDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureInterfacesDialog *_t = static_cast<CaptureInterfacesDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->startCapture(); break;
        case 1: _t->stopCapture(); break;
        case 2: _t->getPoints((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< PointList*(*)>(_a[2]))); break;
        case 3: _t->setSelectedInterfaces(); break;
        case 4: _t->setFilterValid((*reinterpret_cast< bool(*)>(_a[1])),(*reinterpret_cast< const QString(*)>(_a[2]))); break;
        case 5: _t->interfacesChanged(); break;
        case 6: _t->ifsChanged(); break;
        case 7: _t->interfaceListChanged(); break;
        case 8: _t->captureFilterTextEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 9: _t->on_capturePromModeCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 10: _t->on_gbStopCaptureAuto_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 11: _t->on_cbUpdatePacketsRT_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 12: _t->on_cbAutoScroll_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 13: _t->on_gbNewFileAuto_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 14: _t->on_cbExtraCaptureInfo_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 15: _t->on_cbResolveMacAddresses_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 16: _t->on_compileBPF_clicked(); break;
        case 17: _t->on_manageButton_clicked(); break;
        case 18: _t->on_cbResolveNetworkNames_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 19: _t->on_cbResolveTransportNames_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 20: _t->on_buttonBox_accepted(); break;
        case 21: _t->on_buttonBox_rejected(); break;
        case 22: _t->on_buttonBox_helpRequested(); break;
        case 23: _t->interfaceSelected(); break;
        case 24: _t->filterEdited(); break;
        case 25: _t->updateWidgets(); break;
        case 26: _t->updateStatistics(); break;
        case 27: _t->refreshInterfaceList(); break;
        case 28: _t->updateLocalInterfaces(); break;
        case 29: _t->browseButtonClicked(); break;
        case 30: _t->interfaceItemChanged((*reinterpret_cast< QTreeWidgetItem*(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 31: _t->changeEvent((*reinterpret_cast< QEvent*(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::startCapture)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::stopCapture)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)(int , PointList * );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::getPoints)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::setSelectedInterfaces)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)(bool , const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::setFilterValid)) {
                *result = 4;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::interfacesChanged)) {
                *result = 5;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::ifsChanged)) {
                *result = 6;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::interfaceListChanged)) {
                *result = 7;
                return;
            }
        }
        {
            using _t = void (CaptureInterfacesDialog::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureInterfacesDialog::captureFilterTextEdited)) {
                *result = 8;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureInterfacesDialog::staticMetaObject = { {
    &GeometryStateDialog::staticMetaObject,
    qt_meta_stringdata_CaptureInterfacesDialog.data,
    qt_meta_data_CaptureInterfacesDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureInterfacesDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureInterfacesDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureInterfacesDialog.stringdata0))
        return static_cast<void*>(this);
    return GeometryStateDialog::qt_metacast(_clname);
}

int CaptureInterfacesDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = GeometryStateDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 32)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 32;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 32)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 32;
    }
    return _id;
}

// SIGNAL 0
void CaptureInterfacesDialog::startCapture()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void CaptureInterfacesDialog::stopCapture()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void CaptureInterfacesDialog::getPoints(int _t1, PointList * _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void CaptureInterfacesDialog::setSelectedInterfaces()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void CaptureInterfacesDialog::setFilterValid(bool _t1, const QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void CaptureInterfacesDialog::interfacesChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 5, nullptr);
}

// SIGNAL 6
void CaptureInterfacesDialog::ifsChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 6, nullptr);
}

// SIGNAL 7
void CaptureInterfacesDialog::interfaceListChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 7, nullptr);
}

// SIGNAL 8
void CaptureInterfacesDialog::captureFilterTextEdited(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 8, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
