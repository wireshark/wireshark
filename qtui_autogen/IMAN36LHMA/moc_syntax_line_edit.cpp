/****************************************************************************
** Meta object code from reading C++ file 'syntax_line_edit.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/syntax_line_edit.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'syntax_line_edit.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_SyntaxLineEdit_t {
    QByteArrayData data[22];
    char stringdata0[245];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_SyntaxLineEdit_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_SyntaxLineEdit_t qt_meta_stringdata_SyntaxLineEdit = {
    {
QT_MOC_LITERAL(0, 0, 14), // "SyntaxLineEdit"
QT_MOC_LITERAL(1, 15, 13), // "setStyleSheet"
QT_MOC_LITERAL(2, 29, 0), // ""
QT_MOC_LITERAL(3, 30, 11), // "style_sheet"
QT_MOC_LITERAL(4, 42, 12), // "insertFilter"
QT_MOC_LITERAL(5, 55, 6), // "filter"
QT_MOC_LITERAL(6, 62, 18), // "checkDisplayFilter"
QT_MOC_LITERAL(7, 81, 14), // "checkFieldName"
QT_MOC_LITERAL(8, 96, 5), // "field"
QT_MOC_LITERAL(9, 102, 17), // "checkCustomColumn"
QT_MOC_LITERAL(10, 120, 6), // "fields"
QT_MOC_LITERAL(11, 127, 12), // "checkInteger"
QT_MOC_LITERAL(12, 140, 6), // "number"
QT_MOC_LITERAL(13, 147, 21), // "insertFieldCompletion"
QT_MOC_LITERAL(14, 169, 15), // "completion_text"
QT_MOC_LITERAL(15, 185, 11), // "syntaxState"
QT_MOC_LITERAL(16, 197, 11), // "SyntaxState"
QT_MOC_LITERAL(17, 209, 5), // "Empty"
QT_MOC_LITERAL(18, 215, 4), // "Busy"
QT_MOC_LITERAL(19, 220, 7), // "Invalid"
QT_MOC_LITERAL(20, 228, 10), // "Deprecated"
QT_MOC_LITERAL(21, 239, 5) // "Valid"

    },
    "SyntaxLineEdit\0setStyleSheet\0\0style_sheet\0"
    "insertFilter\0filter\0checkDisplayFilter\0"
    "checkFieldName\0field\0checkCustomColumn\0"
    "fields\0checkInteger\0number\0"
    "insertFieldCompletion\0completion_text\0"
    "syntaxState\0SyntaxState\0Empty\0Busy\0"
    "Invalid\0Deprecated\0Valid"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_SyntaxLineEdit[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       1,   70, // properties
       1,   73, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    1,   49,    2, 0x0a /* Public */,
       4,    1,   52,    2, 0x0a /* Public */,
       6,    1,   55,    2, 0x0a /* Public */,
       7,    1,   58,    2, 0x0a /* Public */,
       9,    1,   61,    2, 0x0a /* Public */,
      11,    1,   64,    2, 0x0a /* Public */,
      13,    1,   67,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void, QMetaType::QString,    8,
    QMetaType::Void, QMetaType::QString,   10,
    QMetaType::Void, QMetaType::QString,   12,
    QMetaType::Void, QMetaType::QString,   14,

 // properties: name, type, flags
      15, 0x80000000 | 16, 0x00095009,

 // enums: name, alias, flags, count, data
      16,   16, 0x0,    5,   78,

 // enum data: key, value
      17, uint(SyntaxLineEdit::Empty),
      18, uint(SyntaxLineEdit::Busy),
      19, uint(SyntaxLineEdit::Invalid),
      20, uint(SyntaxLineEdit::Deprecated),
      21, uint(SyntaxLineEdit::Valid),

       0        // eod
};

void SyntaxLineEdit::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        SyntaxLineEdit *_t = static_cast<SyntaxLineEdit *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->setStyleSheet((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->insertFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: _t->checkDisplayFilter((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 3: _t->checkFieldName((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: _t->checkCustomColumn((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 5: _t->checkInteger((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 6: _t->insertFieldCompletion((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        default: ;
        }
    }
#ifndef QT_NO_PROPERTIES
    else if (_c == QMetaObject::ReadProperty) {
        SyntaxLineEdit *_t = static_cast<SyntaxLineEdit *>(_o);
        Q_UNUSED(_t)
        void *_v = _a[0];
        switch (_id) {
        case 0: *reinterpret_cast< SyntaxState*>(_v) = _t->syntaxState(); break;
        default: break;
        }
    } else if (_c == QMetaObject::WriteProperty) {
    } else if (_c == QMetaObject::ResetProperty) {
    }
#endif // QT_NO_PROPERTIES
}

QT_INIT_METAOBJECT const QMetaObject SyntaxLineEdit::staticMetaObject = { {
    &QLineEdit::staticMetaObject,
    qt_meta_stringdata_SyntaxLineEdit.data,
    qt_meta_data_SyntaxLineEdit,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *SyntaxLineEdit::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *SyntaxLineEdit::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_SyntaxLineEdit.stringdata0))
        return static_cast<void*>(this);
    return QLineEdit::qt_metacast(_clname);
}

int SyntaxLineEdit::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QLineEdit::qt_metacall(_c, _id, _a);
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
#ifndef QT_NO_PROPERTIES
   else if (_c == QMetaObject::ReadProperty || _c == QMetaObject::WriteProperty
            || _c == QMetaObject::ResetProperty || _c == QMetaObject::RegisterPropertyMetaType) {
        qt_static_metacall(this, _c, _id, _a);
        _id -= 1;
    } else if (_c == QMetaObject::QueryPropertyDesignable) {
        _id -= 1;
    } else if (_c == QMetaObject::QueryPropertyScriptable) {
        _id -= 1;
    } else if (_c == QMetaObject::QueryPropertyStored) {
        _id -= 1;
    } else if (_c == QMetaObject::QueryPropertyEditable) {
        _id -= 1;
    } else if (_c == QMetaObject::QueryPropertyUser) {
        _id -= 1;
    }
#endif // QT_NO_PROPERTIES
    return _id;
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
