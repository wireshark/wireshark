/****************************************************************************
** Meta object code from reading C++ file 'capture_filter_combo.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/capture_filter_combo.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_filter_combo.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_CaptureFilterCombo_t {
    QByteArrayData data[10];
    char stringdata0[172];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureFilterCombo_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureFilterCombo_t qt_meta_stringdata_CaptureFilterCombo = {
    {
QT_MOC_LITERAL(0, 0, 18), // "CaptureFilterCombo"
QT_MOC_LITERAL(1, 19, 17), // "interfacesChanged"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 22), // "pushFilterSyntaxStatus"
QT_MOC_LITERAL(4, 61, 21), // "popFilterSyntaxStatus"
QT_MOC_LITERAL(5, 83, 26), // "captureFilterSyntaxChanged"
QT_MOC_LITERAL(6, 110, 5), // "valid"
QT_MOC_LITERAL(7, 116, 12), // "startCapture"
QT_MOC_LITERAL(8, 129, 24), // "saveAndRebuildFilterList"
QT_MOC_LITERAL(9, 154, 17) // "rebuildFilterList"

    },
    "CaptureFilterCombo\0interfacesChanged\0"
    "\0pushFilterSyntaxStatus\0popFilterSyntaxStatus\0"
    "captureFilterSyntaxChanged\0valid\0"
    "startCapture\0saveAndRebuildFilterList\0"
    "rebuildFilterList"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureFilterCombo[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       5,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   49,    2, 0x06 /* Public */,
       3,    1,   50,    2, 0x06 /* Public */,
       4,    0,   53,    2, 0x06 /* Public */,
       5,    1,   54,    2, 0x06 /* Public */,
       7,    0,   57,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    0,   58,    2, 0x08 /* Private */,
       9,    0,   59,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,    6,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void CaptureFilterCombo::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureFilterCombo *_t = static_cast<CaptureFilterCombo *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->interfacesChanged(); break;
        case 1: _t->pushFilterSyntaxStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: _t->popFilterSyntaxStatus(); break;
        case 3: _t->captureFilterSyntaxChanged((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->startCapture(); break;
        case 5: _t->saveAndRebuildFilterList(); break;
        case 6: _t->rebuildFilterList(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (CaptureFilterCombo::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterCombo::interfacesChanged)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (CaptureFilterCombo::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterCombo::pushFilterSyntaxStatus)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (CaptureFilterCombo::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterCombo::popFilterSyntaxStatus)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (CaptureFilterCombo::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterCombo::captureFilterSyntaxChanged)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (CaptureFilterCombo::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterCombo::startCapture)) {
                *result = 4;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureFilterCombo::staticMetaObject = { {
    &QComboBox::staticMetaObject,
    qt_meta_stringdata_CaptureFilterCombo.data,
    qt_meta_data_CaptureFilterCombo,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureFilterCombo::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureFilterCombo::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureFilterCombo.stringdata0))
        return static_cast<void*>(this);
    return QComboBox::qt_metacast(_clname);
}

int CaptureFilterCombo::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QComboBox::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}

// SIGNAL 0
void CaptureFilterCombo::interfacesChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void CaptureFilterCombo::pushFilterSyntaxStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void CaptureFilterCombo::popFilterSyntaxStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void CaptureFilterCombo::captureFilterSyntaxChanged(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void CaptureFilterCombo::startCapture()
{
    QMetaObject::activate(this, &staticMetaObject, 4, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
