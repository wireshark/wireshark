/****************************************************************************
** Meta object code from reading C++ file 'filter_expression_toolbar.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/widgets/filter_expression_toolbar.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'filter_expression_toolbar.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_FilterExpressionToolBar_t {
    QByteArrayData data[22];
    char stringdata0[281];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_FilterExpressionToolBar_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_FilterExpressionToolBar_t qt_meta_stringdata_FilterExpressionToolBar = {
    {
QT_MOC_LITERAL(0, 0, 23), // "FilterExpressionToolBar"
QT_MOC_LITERAL(1, 24, 14), // "filterSelected"
QT_MOC_LITERAL(2, 39, 0), // ""
QT_MOC_LITERAL(3, 40, 17), // "filterPreferences"
QT_MOC_LITERAL(4, 58, 10), // "filterEdit"
QT_MOC_LITERAL(5, 69, 8), // "uatIndex"
QT_MOC_LITERAL(6, 78, 24), // "filterExpressionsChanged"
QT_MOC_LITERAL(7, 103, 19), // "onCustomMenuHandler"
QT_MOC_LITERAL(8, 123, 3), // "pos"
QT_MOC_LITERAL(9, 127, 13), // "onActionMoved"
QT_MOC_LITERAL(10, 141, 8), // "QAction*"
QT_MOC_LITERAL(11, 150, 6), // "action"
QT_MOC_LITERAL(12, 157, 6), // "oldPos"
QT_MOC_LITERAL(13, 164, 6), // "newPos"
QT_MOC_LITERAL(14, 171, 15), // "onFilterDropped"
QT_MOC_LITERAL(15, 187, 11), // "description"
QT_MOC_LITERAL(16, 199, 6), // "filter"
QT_MOC_LITERAL(17, 206, 12), // "removeFilter"
QT_MOC_LITERAL(18, 219, 13), // "disableFilter"
QT_MOC_LITERAL(19, 233, 10), // "editFilter"
QT_MOC_LITERAL(20, 244, 13), // "filterClicked"
QT_MOC_LITERAL(21, 258, 22) // "toolBarShowPreferences"

    },
    "FilterExpressionToolBar\0filterSelected\0"
    "\0filterPreferences\0filterEdit\0uatIndex\0"
    "filterExpressionsChanged\0onCustomMenuHandler\0"
    "pos\0onActionMoved\0QAction*\0action\0"
    "oldPos\0newPos\0onFilterDropped\0description\0"
    "filter\0removeFilter\0disableFilter\0"
    "editFilter\0filterClicked\0"
    "toolBarShowPreferences"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_FilterExpressionToolBar[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      12,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    2,   74,    2, 0x06 /* Public */,
       3,    0,   79,    2, 0x06 /* Public */,
       4,    1,   80,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       6,    0,   83,    2, 0x0a /* Public */,
       7,    1,   84,    2, 0x09 /* Protected */,
       9,    3,   87,    2, 0x09 /* Protected */,
      14,    2,   94,    2, 0x09 /* Protected */,
      17,    0,   99,    2, 0x08 /* Private */,
      18,    0,  100,    2, 0x08 /* Private */,
      19,    0,  101,    2, 0x08 /* Private */,
      20,    0,  102,    2, 0x08 /* Private */,
      21,    0,  103,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString, QMetaType::Bool,    2,    2,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,    5,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::QPoint,    8,
    QMetaType::Void, 0x80000000 | 10, QMetaType::Int, QMetaType::Int,   11,   12,   13,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,   15,   16,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void FilterExpressionToolBar::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        FilterExpressionToolBar *_t = static_cast<FilterExpressionToolBar *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->filterSelected((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< bool(*)>(_a[2]))); break;
        case 1: _t->filterPreferences(); break;
        case 2: _t->filterEdit((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->filterExpressionsChanged(); break;
        case 4: _t->onCustomMenuHandler((*reinterpret_cast< const QPoint(*)>(_a[1]))); break;
        case 5: _t->onActionMoved((*reinterpret_cast< QAction*(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2])),(*reinterpret_cast< int(*)>(_a[3]))); break;
        case 6: _t->onFilterDropped((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 7: _t->removeFilter(); break;
        case 8: _t->disableFilter(); break;
        case 9: _t->editFilter(); break;
        case 10: _t->filterClicked(); break;
        case 11: _t->toolBarShowPreferences(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 5:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAction* >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (FilterExpressionToolBar::*)(QString , bool );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FilterExpressionToolBar::filterSelected)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (FilterExpressionToolBar::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FilterExpressionToolBar::filterPreferences)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (FilterExpressionToolBar::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&FilterExpressionToolBar::filterEdit)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject FilterExpressionToolBar::staticMetaObject = { {
    &DragDropToolBar::staticMetaObject,
    qt_meta_stringdata_FilterExpressionToolBar.data,
    qt_meta_data_FilterExpressionToolBar,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *FilterExpressionToolBar::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *FilterExpressionToolBar::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_FilterExpressionToolBar.stringdata0))
        return static_cast<void*>(this);
    return DragDropToolBar::qt_metacast(_clname);
}

int FilterExpressionToolBar::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = DragDropToolBar::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 12)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 12;
    }
    return _id;
}

// SIGNAL 0
void FilterExpressionToolBar::filterSelected(QString _t1, bool _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void FilterExpressionToolBar::filterPreferences()
{
    QMetaObject::activate(this, &staticMetaObject, 1, nullptr);
}

// SIGNAL 2
void FilterExpressionToolBar::filterEdit(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
