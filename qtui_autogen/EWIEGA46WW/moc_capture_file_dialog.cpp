/****************************************************************************
** Meta object code from reading C++ file 'capture_file_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/capture_file_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_file_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_CaptureFileDialog_t {
    QByteArrayData data[20];
    char stringdata0[225];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureFileDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureFileDialog_t qt_meta_stringdata_CaptureFileDialog = {
    {
QT_MOC_LITERAL(0, 0, 17), // "CaptureFileDialog"
QT_MOC_LITERAL(1, 18, 6), // "accept"
QT_MOC_LITERAL(2, 25, 0), // ""
QT_MOC_LITERAL(3, 26, 4), // "exec"
QT_MOC_LITERAL(4, 31, 4), // "open"
QT_MOC_LITERAL(5, 36, 8), // "QString&"
QT_MOC_LITERAL(6, 45, 9), // "file_name"
QT_MOC_LITERAL(7, 55, 5), // "uint&"
QT_MOC_LITERAL(8, 61, 4), // "type"
QT_MOC_LITERAL(9, 66, 6), // "saveAs"
QT_MOC_LITERAL(10, 73, 18), // "check_savability_t"
QT_MOC_LITERAL(11, 92, 21), // "must_support_comments"
QT_MOC_LITERAL(12, 114, 21), // "exportSelectedPackets"
QT_MOC_LITERAL(13, 136, 15), // "packet_range_t*"
QT_MOC_LITERAL(14, 152, 5), // "range"
QT_MOC_LITERAL(15, 158, 5), // "merge"
QT_MOC_LITERAL(16, 164, 20), // "fixFilenameExtension"
QT_MOC_LITERAL(17, 185, 7), // "preview"
QT_MOC_LITERAL(18, 193, 4), // "path"
QT_MOC_LITERAL(19, 198, 26) // "on_buttonBox_helpRequested"

    },
    "CaptureFileDialog\0accept\0\0exec\0open\0"
    "QString&\0file_name\0uint&\0type\0saveAs\0"
    "check_savability_t\0must_support_comments\0"
    "exportSelectedPackets\0packet_range_t*\0"
    "range\0merge\0fixFilenameExtension\0"
    "preview\0path\0on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureFileDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   59,    2, 0x0a /* Public */,
       3,    0,   60,    2, 0x0a /* Public */,
       4,    2,   61,    2, 0x0a /* Public */,
       9,    2,   66,    2, 0x0a /* Public */,
      12,    2,   71,    2, 0x0a /* Public */,
      15,    1,   76,    2, 0x0a /* Public */,
      16,    0,   79,    2, 0x08 /* Private */,
      17,    1,   80,    2, 0x08 /* Private */,
      19,    0,   83,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Int,
    QMetaType::Int, 0x80000000 | 5, 0x80000000 | 7,    6,    8,
    0x80000000 | 10, 0x80000000 | 5, QMetaType::Bool,    6,   11,
    0x80000000 | 10, 0x80000000 | 5, 0x80000000 | 13,    6,   14,
    QMetaType::Int, 0x80000000 | 5,    6,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   18,
    QMetaType::Void,

       0        // eod
};

void CaptureFileDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureFileDialog *_t = static_cast<CaptureFileDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->accept(); break;
        case 1: { int _r = _t->exec();
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 2: { int _r = _t->open((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< uint(*)>(_a[2])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 3: { check_savability_t _r = _t->saveAs((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2])));
            if (_a[0]) *reinterpret_cast< check_savability_t*>(_a[0]) = std::move(_r); }  break;
        case 4: { check_savability_t _r = _t->exportSelectedPackets((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< packet_range_t*(*)>(_a[2])));
            if (_a[0]) *reinterpret_cast< check_savability_t*>(_a[0]) = std::move(_r); }  break;
        case 5: { int _r = _t->merge((*reinterpret_cast< QString(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = std::move(_r); }  break;
        case 6: _t->fixFilenameExtension(); break;
        case 7: _t->preview((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 8: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureFileDialog::staticMetaObject = { {
    &QFileDialog::staticMetaObject,
    qt_meta_stringdata_CaptureFileDialog.data,
    qt_meta_data_CaptureFileDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureFileDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureFileDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureFileDialog.stringdata0))
        return static_cast<void*>(this);
    return QFileDialog::qt_metacast(_clname);
}

int CaptureFileDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QFileDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 9)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 9;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 9)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 9;
    }
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
