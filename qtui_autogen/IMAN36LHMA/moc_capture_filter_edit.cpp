/****************************************************************************
** Meta object code from reading C++ file 'capture_filter_edit.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/capture_filter_edit.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'capture_filter_edit.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_CaptureFilterEdit_t {
    QByteArrayData data[21];
    char stringdata0[292];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_CaptureFilterEdit_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_CaptureFilterEdit_t qt_meta_stringdata_CaptureFilterEdit = {
    {
QT_MOC_LITERAL(0, 0, 17), // "CaptureFilterEdit"
QT_MOC_LITERAL(1, 18, 22), // "pushFilterSyntaxStatus"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 21), // "popFilterSyntaxStatus"
QT_MOC_LITERAL(4, 64, 26), // "captureFilterSyntaxChanged"
QT_MOC_LITERAL(5, 91, 5), // "valid"
QT_MOC_LITERAL(6, 97, 12), // "startCapture"
QT_MOC_LITERAL(7, 110, 11), // "addBookmark"
QT_MOC_LITERAL(8, 122, 6), // "filter"
QT_MOC_LITERAL(9, 129, 11), // "checkFilter"
QT_MOC_LITERAL(10, 141, 18), // "updateBookmarkMenu"
QT_MOC_LITERAL(11, 160, 10), // "saveFilter"
QT_MOC_LITERAL(12, 171, 12), // "removeFilter"
QT_MOC_LITERAL(13, 184, 11), // "showFilters"
QT_MOC_LITERAL(14, 196, 13), // "prepareFilter"
QT_MOC_LITERAL(15, 210, 18), // "applyCaptureFilter"
QT_MOC_LITERAL(16, 229, 20), // "setFilterSyntaxState"
QT_MOC_LITERAL(17, 250, 5), // "state"
QT_MOC_LITERAL(18, 256, 7), // "err_msg"
QT_MOC_LITERAL(19, 264, 15), // "bookmarkClicked"
QT_MOC_LITERAL(20, 280, 11) // "clearFilter"

    },
    "CaptureFilterEdit\0pushFilterSyntaxStatus\0"
    "\0popFilterSyntaxStatus\0"
    "captureFilterSyntaxChanged\0valid\0"
    "startCapture\0addBookmark\0filter\0"
    "checkFilter\0updateBookmarkMenu\0"
    "saveFilter\0removeFilter\0showFilters\0"
    "prepareFilter\0applyCaptureFilter\0"
    "setFilterSyntaxState\0state\0err_msg\0"
    "bookmarkClicked\0clearFilter"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_CaptureFilterEdit[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       5,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   94,    2, 0x06 /* Public */,
       3,    0,   97,    2, 0x06 /* Public */,
       4,    1,   98,    2, 0x06 /* Public */,
       6,    0,  101,    2, 0x06 /* Public */,
       7,    1,  102,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    0,  105,    2, 0x0a /* Public */,
      10,    0,  106,    2, 0x0a /* Public */,
      11,    0,  107,    2, 0x0a /* Public */,
      12,    0,  108,    2, 0x0a /* Public */,
      13,    0,  109,    2, 0x0a /* Public */,
      14,    0,  110,    2, 0x0a /* Public */,
      15,    0,  111,    2, 0x08 /* Private */,
       9,    1,  112,    2, 0x08 /* Private */,
      16,    3,  115,    2, 0x08 /* Private */,
      19,    0,  122,    2, 0x08 /* Private */,
      20,    0,  123,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,    5,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    8,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    8,
    QMetaType::Void, QMetaType::QString, QMetaType::Int, QMetaType::QString,    8,   17,   18,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void CaptureFilterEdit::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        CaptureFilterEdit *_t = static_cast<CaptureFilterEdit *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->pushFilterSyntaxStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->popFilterSyntaxStatus(); break;
        case 2: _t->captureFilterSyntaxChanged((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 3: _t->startCapture(); break;
        case 4: _t->addBookmark((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 5: _t->checkFilter(); break;
        case 6: _t->updateBookmarkMenu(); break;
        case 7: _t->saveFilter(); break;
        case 8: _t->removeFilter(); break;
        case 9: _t->showFilters(); break;
        case 10: _t->prepareFilter(); break;
        case 11: _t->applyCaptureFilter(); break;
        case 12: _t->checkFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 13: _t->setFilterSyntaxState((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< QString(*)>(_a[3]))); break;
        case 14: _t->bookmarkClicked(); break;
        case 15: _t->clearFilter(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (CaptureFilterEdit::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterEdit::pushFilterSyntaxStatus)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (CaptureFilterEdit::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterEdit::popFilterSyntaxStatus)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (CaptureFilterEdit::*)(bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterEdit::captureFilterSyntaxChanged)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (CaptureFilterEdit::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterEdit::startCapture)) {
                *result = 3;
                return;
            }
        }
        {
            using _t = void (CaptureFilterEdit::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&CaptureFilterEdit::addBookmark)) {
                *result = 4;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject CaptureFilterEdit::staticMetaObject = { {
    &SyntaxLineEdit::staticMetaObject,
    qt_meta_stringdata_CaptureFilterEdit.data,
    qt_meta_data_CaptureFilterEdit,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *CaptureFilterEdit::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *CaptureFilterEdit::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_CaptureFilterEdit.stringdata0))
        return static_cast<void*>(this);
    return SyntaxLineEdit::qt_metacast(_clname);
}

int CaptureFilterEdit::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = SyntaxLineEdit::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void CaptureFilterEdit::pushFilterSyntaxStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void CaptureFilterEdit::popFilterSyntaxStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void CaptureFilterEdit::captureFilterSyntaxChanged(bool _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void CaptureFilterEdit::startCapture()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}

// SIGNAL 4
void CaptureFilterEdit::addBookmark(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
