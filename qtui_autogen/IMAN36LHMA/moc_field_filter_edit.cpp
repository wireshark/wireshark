/****************************************************************************
** Meta object code from reading C++ file 'field_filter_edit.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/field_filter_edit.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'field_filter_edit.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_FieldFilterEdit_t {
    QByteArrayData data[17];
    char stringdata0[224];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_FieldFilterEdit_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_FieldFilterEdit_t qt_meta_stringdata_FieldFilterEdit = {
    {
QT_MOC_LITERAL(0, 0, 15), // "FieldFilterEdit"
QT_MOC_LITERAL(1, 16, 22), // "pushFilterSyntaxStatus"
QT_MOC_LITERAL(2, 39, 0), // ""
QT_MOC_LITERAL(3, 40, 21), // "popFilterSyntaxStatus"
QT_MOC_LITERAL(4, 62, 23), // "pushFilterSyntaxWarning"
QT_MOC_LITERAL(5, 86, 13), // "filterPackets"
QT_MOC_LITERAL(6, 100, 10), // "new_filter"
QT_MOC_LITERAL(7, 111, 5), // "force"
QT_MOC_LITERAL(8, 117, 11), // "checkFilter"
QT_MOC_LITERAL(9, 129, 18), // "applyDisplayFilter"
QT_MOC_LITERAL(10, 148, 11), // "filter_text"
QT_MOC_LITERAL(11, 160, 11), // "clearFilter"
QT_MOC_LITERAL(12, 172, 11), // "changeEvent"
QT_MOC_LITERAL(13, 184, 7), // "QEvent*"
QT_MOC_LITERAL(14, 192, 5), // "event"
QT_MOC_LITERAL(15, 198, 11), // "showFilters"
QT_MOC_LITERAL(16, 210, 13) // "prepareFilter"

    },
    "FieldFilterEdit\0pushFilterSyntaxStatus\0"
    "\0popFilterSyntaxStatus\0pushFilterSyntaxWarning\0"
    "filterPackets\0new_filter\0force\0"
    "checkFilter\0applyDisplayFilter\0"
    "filter_text\0clearFilter\0changeEvent\0"
    "QEvent*\0event\0showFilters\0prepareFilter"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_FieldFilterEdit[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x06 /* Public */,
       3,    0,   72,    2, 0x06 /* Public */,
       4,    1,   73,    2, 0x06 /* Public */,
       5,    2,   76,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    0,   81,    2, 0x0a /* Public */,
       9,    0,   82,    2, 0x0a /* Public */,
       8,    1,   83,    2, 0x08 /* Private */,
      11,    0,   86,    2, 0x08 /* Private */,
      12,    1,   87,    2, 0x08 /* Private */,
      15,    0,   90,    2, 0x08 /* Private */,
      16,    0,   91,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    6,    7,

 // slots: parameters
    QMetaType::Bool,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   10,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 13,   14,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void FieldFilterEdit::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        FieldFilterEdit *_t = static_cast<FieldFilterEdit *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->pushFilterSyntaxStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->popFilterSyntaxStatus(); break;
        case 2: _t->pushFilterSyntaxWarning((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 3: _t->filterPackets((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 4: { bool _r = _t->checkFilter();
            if (_a[0]) *reinterpret_cast< bool*>(_a[0]) = std::move(_r); }  break;
        case 5: _t->applyDisplayFilter(); break;
        case 6: _t->checkFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 7: _t->clearFilter(); break;
        case 8: _t->changeEvent((*reinterpret_cast< QEvent*(*)>(_a[1]))); break;
        case 9: _t->showFilters(); break;
        case 10: _t->prepareFilter(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (FieldFilterEdit::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FieldFilterEdit::pushFilterSyntaxStatus)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (FieldFilterEdit::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FieldFilterEdit::popFilterSyntaxStatus)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (FieldFilterEdit::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FieldFilterEdit::pushFilterSyntaxWarning)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (FieldFilterEdit::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FieldFilterEdit::filterPackets)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject FieldFilterEdit::staticMetaObject = { {
    &SyntaxLineEdit::staticMetaObject,
    qt_meta_stringdata_FieldFilterEdit.data,
    qt_meta_data_FieldFilterEdit,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *FieldFilterEdit::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FieldFilterEdit::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_FieldFilterEdit.stringdata0))
        return static_cast<void*>(this);
    return SyntaxLineEdit::qt_metacast(_clname);
}

int FieldFilterEdit::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = SyntaxLineEdit::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 11)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 11;
    }
    return _id;
}

// SIGNAL 0
void FieldFilterEdit::pushFilterSyntaxStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void FieldFilterEdit::popFilterSyntaxStatus()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void FieldFilterEdit::pushFilterSyntaxWarning(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void FieldFilterEdit::filterPackets(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
