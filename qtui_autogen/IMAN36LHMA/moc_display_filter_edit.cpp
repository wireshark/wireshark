/****************************************************************************
** Meta object code from reading C++ file 'display_filter_edit.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/display_filter_edit.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'display_filter_edit.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_DisplayFilterEdit_t {
    QByteArrayData data[24];
    char stringdata0[333];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_DisplayFilterEdit_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_DisplayFilterEdit_t qt_meta_stringdata_DisplayFilterEdit = {
    {
QT_MOC_LITERAL(0, 0, 17), // "DisplayFilterEdit"
QT_MOC_LITERAL(1, 18, 22), // "pushFilterSyntaxStatus"
QT_MOC_LITERAL(2, 41, 0), // ""
QT_MOC_LITERAL(3, 42, 21), // "popFilterSyntaxStatus"
QT_MOC_LITERAL(4, 64, 13), // "filterPackets"
QT_MOC_LITERAL(5, 78, 10), // "new_filter"
QT_MOC_LITERAL(6, 89, 5), // "force"
QT_MOC_LITERAL(7, 95, 21), // "showPreferencesDialog"
QT_MOC_LITERAL(8, 117, 9), // "pane_name"
QT_MOC_LITERAL(9, 127, 11), // "checkFilter"
QT_MOC_LITERAL(10, 139, 18), // "updateBookmarkMenu"
QT_MOC_LITERAL(11, 158, 18), // "applyDisplayFilter"
QT_MOC_LITERAL(12, 177, 20), // "displayFilterSuccess"
QT_MOC_LITERAL(13, 198, 7), // "success"
QT_MOC_LITERAL(14, 206, 11), // "filter_text"
QT_MOC_LITERAL(15, 218, 11), // "clearFilter"
QT_MOC_LITERAL(16, 230, 11), // "changeEvent"
QT_MOC_LITERAL(17, 242, 7), // "QEvent*"
QT_MOC_LITERAL(18, 250, 5), // "event"
QT_MOC_LITERAL(19, 256, 10), // "saveFilter"
QT_MOC_LITERAL(20, 267, 12), // "removeFilter"
QT_MOC_LITERAL(21, 280, 11), // "showFilters"
QT_MOC_LITERAL(22, 292, 19), // "showExpressionPrefs"
QT_MOC_LITERAL(23, 312, 20) // "applyOrPrepareFilter"

    },
    "DisplayFilterEdit\0pushFilterSyntaxStatus\0"
    "\0popFilterSyntaxStatus\0filterPackets\0"
    "new_filter\0force\0showPreferencesDialog\0"
    "pane_name\0checkFilter\0updateBookmarkMenu\0"
    "applyDisplayFilter\0displayFilterSuccess\0"
    "success\0filter_text\0clearFilter\0"
    "changeEvent\0QEvent*\0event\0saveFilter\0"
    "removeFilter\0showFilters\0showExpressionPrefs\0"
    "applyOrPrepareFilter"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_DisplayFilterEdit[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      16,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   94,    2, 0x06 /* Public */,
       3,    0,   97,    2, 0x06 /* Public */,
       4,    2,   98,    2, 0x06 /* Public */,
       7,    1,  103,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       9,    0,  106,    2, 0x0a /* Public */,
      10,    0,  107,    2, 0x0a /* Public */,
      11,    0,  108,    2, 0x0a /* Public */,
      12,    1,  109,    2, 0x0a /* Public */,
       9,    1,  112,    2, 0x08 /* Private */,
      15,    0,  115,    2, 0x08 /* Private */,
      16,    1,  116,    2, 0x08 /* Private */,
      19,    0,  119,    2, 0x08 /* Private */,
      20,    0,  120,    2, 0x08 /* Private */,
      21,    0,  121,    2, 0x08 /* Private */,
      22,    0,  122,    2, 0x08 /* Private */,
      23,    0,  123,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    5,    6,
    QMetaType::Void, QMetaType::QString,    8,

 // slots: parameters
    QMetaType::Bool,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool,   13,
    QMetaType::Void, QMetaType::QString,   14,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 17,   18,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void DisplayFilterEdit::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        DisplayFilterEdit *_t = static_cast<DisplayFilterEdit *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->pushFilterSyntaxStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->popFilterSyntaxStatus(); break;
        case 2: _t->filterPackets((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 3: _t->showPreferencesDialog((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 4: { bool _r = _t->checkFilter();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 5: _t->updateBookmarkMenu(); break;
        case 6: _t->applyDisplayFilter(); break;
        case 7: _t->displayFilterSuccess((*reinterpret_cast< bool(*)>(_a[1]))); break;
        case 8: _t->checkFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 9: _t->clearFilter(); break;
        case 10: _t->changeEvent((*reinterpret_cast< QEvent*(*)>(_a[1]))); break;
        case 11: _t->saveFilter(); break;
        case 12: _t->removeFilter(); break;
        case 13: _t->showFilters(); break;
        case 14: _t->showExpressionPrefs(); break;
        case 15: _t->applyOrPrepareFilter(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (DisplayFilterEdit::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&DisplayFilterEdit::pushFilterSyntaxStatus)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (DisplayFilterEdit::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&DisplayFilterEdit::popFilterSyntaxStatus)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (DisplayFilterEdit::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&DisplayFilterEdit::filterPackets)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (DisplayFilterEdit::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&DisplayFilterEdit::showPreferencesDialog)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject DisplayFilterEdit::staticMetaObject = { {
    &SyntaxLineEdit::staticMetaObject,
    qt_meta_stringdata_DisplayFilterEdit.data,
    qt_meta_data_DisplayFilterEdit,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *DisplayFilterEdit::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *DisplayFilterEdit::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_DisplayFilterEdit.stringdata0))
        return static_cast<void*>(this);
    return SyntaxLineEdit::qt_metacast(_clname);
}

int DisplayFilterEdit::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
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
void DisplayFilterEdit::pushFilterSyntaxStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void DisplayFilterEdit::popFilterSyntaxStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void DisplayFilterEdit::filterPackets(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void DisplayFilterEdit::showPreferencesDialog(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
