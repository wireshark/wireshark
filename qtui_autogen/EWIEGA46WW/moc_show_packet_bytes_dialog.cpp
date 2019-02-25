/****************************************************************************
** Meta object code from reading C++ file 'show_packet_bytes_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/show_packet_bytes_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'show_packet_bytes_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ShowPacketBytesDialog_t {
    QByteArrayData data[23];
    char stringdata0[329];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ShowPacketBytesDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ShowPacketBytesDialog_t qt_meta_stringdata_ShowPacketBytesDialog = {
    {
QT_MOC_LITERAL(0, 0, 21), // "ShowPacketBytesDialog"
QT_MOC_LITERAL(1, 22, 18), // "captureFileClosing"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 23), // "on_sbStart_valueChanged"
QT_MOC_LITERAL(4, 66, 5), // "value"
QT_MOC_LITERAL(5, 72, 21), // "on_sbEnd_valueChanged"
QT_MOC_LITERAL(6, 94, 33), // "on_cbDecodeAs_currentIndexCha..."
QT_MOC_LITERAL(7, 128, 3), // "idx"
QT_MOC_LITERAL(8, 132, 31), // "on_cbShowAs_currentIndexChanged"
QT_MOC_LITERAL(9, 164, 23), // "on_leFind_returnPressed"
QT_MOC_LITERAL(10, 188, 16), // "on_bFind_clicked"
QT_MOC_LITERAL(11, 205, 21), // "on_buttonBox_rejected"
QT_MOC_LITERAL(12, 227, 12), // "showSelected"
QT_MOC_LITERAL(13, 240, 5), // "start"
QT_MOC_LITERAL(14, 246, 3), // "end"
QT_MOC_LITERAL(15, 250, 12), // "useRegexFind"
QT_MOC_LITERAL(16, 263, 9), // "use_regex"
QT_MOC_LITERAL(17, 273, 8), // "findText"
QT_MOC_LITERAL(18, 282, 7), // "go_back"
QT_MOC_LITERAL(19, 290, 10), // "helpButton"
QT_MOC_LITERAL(20, 301, 10), // "printBytes"
QT_MOC_LITERAL(21, 312, 9), // "copyBytes"
QT_MOC_LITERAL(22, 322, 6) // "saveAs"

    },
    "ShowPacketBytesDialog\0captureFileClosing\0"
    "\0on_sbStart_valueChanged\0value\0"
    "on_sbEnd_valueChanged\0"
    "on_cbDecodeAs_currentIndexChanged\0idx\0"
    "on_cbShowAs_currentIndexChanged\0"
    "on_leFind_returnPressed\0on_bFind_clicked\0"
    "on_buttonBox_rejected\0showSelected\0"
    "start\0end\0useRegexFind\0use_regex\0"
    "findText\0go_back\0helpButton\0printBytes\0"
    "copyBytes\0saveAs"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ShowPacketBytesDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   94,    2, 0x0a /* Public */,
       3,    1,   95,    2, 0x08 /* Private */,
       5,    1,   98,    2, 0x08 /* Private */,
       6,    1,  101,    2, 0x08 /* Private */,
       8,    1,  104,    2, 0x08 /* Private */,
       9,    0,  107,    2, 0x08 /* Private */,
      10,    0,  108,    2, 0x08 /* Private */,
      11,    0,  109,    2, 0x08 /* Private */,
      12,    2,  110,    2, 0x08 /* Private */,
      15,    1,  115,    2, 0x08 /* Private */,
      17,    1,  118,    2, 0x08 /* Private */,
      17,    0,  121,    2, 0x28 /* Private | MethodCloned */,
      19,    0,  122,    2, 0x08 /* Private */,
      20,    0,  123,    2, 0x08 /* Private */,
      21,    0,  124,    2, 0x08 /* Private */,
      22,    0,  125,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    4,
    QMetaType::Void, QMetaType::Int,    4,
    QMetaType::Void, QMetaType::Int,    7,
    QMetaType::Void, QMetaType::Int,    7,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int, QMetaType::Int,   13,   14,
    QMetaType::Void, QMetaType::Bool,   16,
    QMetaType::Void, QMetaType::Bool,   18,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ShowPacketBytesDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ShowPacketBytesDialog *_t = static_cast<ShowPacketBytesDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->captureFileClosing(); break;
        case 1: _t->on_sbStart_valueChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->on_sbEnd_valueChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->on_cbDecodeAs_currentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->on_cbShowAs_currentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 5: _t->on_leFind_returnPressed(); break;
        case 6: _t->on_bFind_clicked(); break;
        case 7: _t->on_buttonBox_rejected(); break;
        case 8: _t->showSelected((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 9: _t->useRegexFind((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 10: _t->findText((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 11: _t->findText(); break;
        case 12: _t->helpButton(); break;
        case 13: _t->printBytes(); break;
        case 14: _t->copyBytes(); break;
        case 15: _t->saveAs(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ShowPacketBytesDialog::staticMetaObject = { {
    &WiresharkDialog::staticMetaObject,
    qt_meta_stringdata_ShowPacketBytesDialog.data,
    qt_meta_data_ShowPacketBytesDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ShowPacketBytesDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ShowPacketBytesDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ShowPacketBytesDialog.stringdata0))
        return static_cast<void*>(this);
    return WiresharkDialog::qt_metacast(_clname);
}

int ShowPacketBytesDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = WiresharkDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 16)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 16;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 16)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 16;
    }
    return _id;
}
struct qt_meta_stringdata_ShowPacketBytesTextEdit_t {
    QByteArrayData data[7];
    char stringdata0[88];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ShowPacketBytesTextEdit_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ShowPacketBytesTextEdit_t qt_meta_stringdata_ShowPacketBytesTextEdit = {
    {
QT_MOC_LITERAL(0, 0, 23), // "ShowPacketBytesTextEdit"
QT_MOC_LITERAL(1, 24, 12), // "showSelected"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 16), // "contextMenuEvent"
QT_MOC_LITERAL(4, 55, 18), // "QContextMenuEvent*"
QT_MOC_LITERAL(5, 74, 5), // "event"
QT_MOC_LITERAL(6, 80, 7) // "showAll"

    },
    "ShowPacketBytesTextEdit\0showSelected\0"
    "\0contextMenuEvent\0QContextMenuEvent*\0"
    "event\0showAll"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ShowPacketBytesTextEdit[] = {

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
       1,    2,   34,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       3,    1,   39,    2, 0x08 /* Private */,
       1,    0,   42,    2, 0x08 /* Private */,
       6,    0,   43,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Int, QMetaType::Int,    2,    2,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 4,    5,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ShowPacketBytesTextEdit::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ShowPacketBytesTextEdit *_t = static_cast<ShowPacketBytesTextEdit *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->showSelected((*reinterpret_cast< int(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 1: _t->contextMenuEvent((*reinterpret_cast< QContextMenuEvent*(*)>(_a[1]))); break;
        case 2: _t->showSelected(); break;
        case 3: _t->showAll(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (ShowPacketBytesTextEdit::*)(int , int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&ShowPacketBytesTextEdit::showSelected)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ShowPacketBytesTextEdit::staticMetaObject = { {
    &QTextEdit::staticMetaObject,
    qt_meta_stringdata_ShowPacketBytesTextEdit.data,
    qt_meta_data_ShowPacketBytesTextEdit,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ShowPacketBytesTextEdit::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ShowPacketBytesTextEdit::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ShowPacketBytesTextEdit.stringdata0))
        return static_cast<void*>(this);
    return QTextEdit::qt_metacast(_clname);
}

int ShowPacketBytesTextEdit::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QTextEdit::qt_metacall(_c, _id, _a);
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
void ShowPacketBytesTextEdit::showSelected(int _t1, int _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
