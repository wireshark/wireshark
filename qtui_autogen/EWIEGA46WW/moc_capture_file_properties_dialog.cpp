/****************************************************************************
** Meta object code from reading C++ file 'capture_file_properties_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/capture_file_properties_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_file_properties_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_CaptureFilePropertiesDialog_t {
    QByteArrayData data[13];
    char stringdata0[207];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureFilePropertiesDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureFilePropertiesDialog_t qt_meta_stringdata_CaptureFilePropertiesDialog = {
    {
QT_MOC_LITERAL(0, 0, 27), // "CaptureFilePropertiesDialog"
QT_MOC_LITERAL(1, 28, 21), // "captureCommentChanged"
QT_MOC_LITERAL(2, 50, 0), // ""
QT_MOC_LITERAL(3, 51, 11), // "changeEvent"
QT_MOC_LITERAL(4, 63, 7), // "QEvent*"
QT_MOC_LITERAL(5, 71, 5), // "event"
QT_MOC_LITERAL(6, 77, 13), // "updateWidgets"
QT_MOC_LITERAL(7, 91, 26), // "on_buttonBox_helpRequested"
QT_MOC_LITERAL(8, 118, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(9, 140, 20), // "on_buttonBox_clicked"
QT_MOC_LITERAL(10, 161, 16), // "QAbstractButton*"
QT_MOC_LITERAL(11, 178, 6), // "button"
QT_MOC_LITERAL(12, 185, 21) // "on_buttonBox_rejected"

    },
    "CaptureFilePropertiesDialog\0"
    "captureCommentChanged\0\0changeEvent\0"
    "QEvent*\0event\0updateWidgets\0"
    "on_buttonBox_helpRequested\0"
    "on_buttonBox_accepted\0on_buttonBox_clicked\0"
    "QAbstractButton*\0button\0on_buttonBox_rejected"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureFilePropertiesDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   49,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    1,   50,    2, 0x09 /* Protected */,
       6,    0,   53,    2, 0x08 /* Private */,
       7,    0,   54,    2, 0x08 /* Private */,
       8,    0,   55,    2, 0x08 /* Private */,
       9,    1,   56,    2, 0x08 /* Private */,
      12,    0,   59,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 10,   11,
    QMetaType::Void,

       0        // eod
};

void CaptureFilePropertiesDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureFilePropertiesDialog *_t = static_cast<CaptureFilePropertiesDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->captureCommentChanged(); break;
        case 1: _t->changeEvent((*reinterpret_cast< QEvent*(*)>(_a[1]))); break;
        case 2: _t->updateWidgets(); break;
        case 3: _t->on_buttonBox_helpRequested(); break;
        case 4: _t->on_buttonBox_accepted(); break;
        case 5: _t->on_buttonBox_clicked((*reinterpret_cast< QAbstractButton*(*)>(_a[1]))); break;
        case 6: _t->on_buttonBox_rejected(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (CaptureFilePropertiesDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilePropertiesDialog::captureCommentChanged)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureFilePropertiesDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_CaptureFilePropertiesDialog.data,
    qt_meta_data_CaptureFilePropertiesDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureFilePropertiesDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureFilePropertiesDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureFilePropertiesDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int CaptureFilePropertiesDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
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
void CaptureFilePropertiesDialog::captureCommentChanged()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
