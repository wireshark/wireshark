/****************************************************************************
** Meta object code from reading C++ file 'time_shift_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/time_shift_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'time_shift_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_TimeShiftDialog_t {
    QByteArrayData data[22];
    char stringdata0[424];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_TimeShiftDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_TimeShiftDialog_t qt_meta_stringdata_TimeShiftDialog = {
    {
QT_MOC_LITERAL(0, 0, 15), // "TimeShiftDialog"
QT_MOC_LITERAL(1, 16, 11), // "timeShifted"
QT_MOC_LITERAL(2, 28, 0), // ""
QT_MOC_LITERAL(3, 29, 14), // "setCaptureFile"
QT_MOC_LITERAL(4, 44, 13), // "capture_file*"
QT_MOC_LITERAL(5, 58, 2), // "cf"
QT_MOC_LITERAL(6, 61, 25), // "on_shiftAllButton_toggled"
QT_MOC_LITERAL(7, 87, 7), // "checked"
QT_MOC_LITERAL(8, 95, 23), // "on_setOneButton_toggled"
QT_MOC_LITERAL(9, 119, 27), // "on_unshiftAllButton_toggled"
QT_MOC_LITERAL(10, 147, 25), // "on_setTwoCheckBox_toggled"
QT_MOC_LITERAL(11, 173, 35), // "on_shiftAllTimeLineEdit_textC..."
QT_MOC_LITERAL(12, 209, 7), // "sa_text"
QT_MOC_LITERAL(13, 217, 33), // "on_setOneTimeLineEdit_textCha..."
QT_MOC_LITERAL(14, 251, 7), // "so_text"
QT_MOC_LITERAL(15, 259, 34), // "on_setOneFrameLineEdit_textCh..."
QT_MOC_LITERAL(16, 294, 10), // "frame_text"
QT_MOC_LITERAL(17, 305, 34), // "on_setTwoFrameLineEdit_textCh..."
QT_MOC_LITERAL(18, 340, 33), // "on_setTwoTimeLineEdit_textCha..."
QT_MOC_LITERAL(19, 374, 7), // "st_text"
QT_MOC_LITERAL(20, 382, 14), // "applyTimeShift"
QT_MOC_LITERAL(21, 397, 26) // "on_buttonBox_helpRequested"

    },
    "TimeShiftDialog\0timeShifted\0\0"
    "setCaptureFile\0capture_file*\0cf\0"
    "on_shiftAllButton_toggled\0checked\0"
    "on_setOneButton_toggled\0"
    "on_unshiftAllButton_toggled\0"
    "on_setTwoCheckBox_toggled\0"
    "on_shiftAllTimeLineEdit_textChanged\0"
    "sa_text\0on_setOneTimeLineEdit_textChanged\0"
    "so_text\0on_setOneFrameLineEdit_textChanged\0"
    "frame_text\0on_setTwoFrameLineEdit_textChanged\0"
    "on_setTwoTimeLineEdit_textChanged\0"
    "st_text\0applyTimeShift\0"
    "on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_TimeShiftDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      13,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   79,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    1,   80,    2, 0x0a /* Public */,
       6,    1,   83,    2, 0x08 /* Private */,
       8,    1,   86,    2, 0x08 /* Private */,
       9,    1,   89,    2, 0x08 /* Private */,
      10,    1,   92,    2, 0x08 /* Private */,
      11,    1,   95,    2, 0x08 /* Private */,
      13,    1,   98,    2, 0x08 /* Private */,
      15,    1,  101,    2, 0x08 /* Private */,
      17,    1,  104,    2, 0x08 /* Private */,
      18,    1,  107,    2, 0x08 /* Private */,
      20,    0,  110,    2, 0x08 /* Private */,
      21,    0,  111,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void, QMetaType::Bool,    7,
    QMetaType::Void, QMetaType::Bool,    7,
    QMetaType::Void, QMetaType::Bool,    7,
    QMetaType::Void, QMetaType::Bool,    7,
    QMetaType::Void, QMetaType::QString,   12,
    QMetaType::Void, QMetaType::QString,   14,
    QMetaType::Void, QMetaType::QString,   16,
    QMetaType::Void, QMetaType::QString,   16,
    QMetaType::Void, QMetaType::QString,   19,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void TimeShiftDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        TimeShiftDialog *_t = static_cast<TimeShiftDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->timeShifted(); break;
        case 1: _t->setCaptureFile((*reinterpret_cast< capture_file*(*)>(_a[1]))); break;
        case 2: _t->on_shiftAllButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->on_setOneButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 4: _t->on_unshiftAllButton_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 5: _t->on_setTwoCheckBox_toggled((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 6: _t->on_shiftAllTimeLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 7: _t->on_setOneTimeLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 8: _t->on_setOneFrameLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 9: _t->on_setTwoFrameLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 10: _t->on_setTwoTimeLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 11: _t->applyTimeShift(); break;
        case 12: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (TimeShiftDialog::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&TimeShiftDialog::timeShifted)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject TimeShiftDialog::staticMetaObject = { {
    &QDialog::staticMetaObject,
    qt_meta_stringdata_TimeShiftDialog.data,
    qt_meta_data_TimeShiftDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *TimeShiftDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *TimeShiftDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_TimeShiftDialog.stringdata0))
        return static_cast<void*>(this);
    return QDialog::qt_metacast(_clname);
}

int TimeShiftDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 13)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 13;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 13)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 13;
    }
    return _id;
}

// SIGNAL 0
void TimeShiftDialog::timeShifted()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
