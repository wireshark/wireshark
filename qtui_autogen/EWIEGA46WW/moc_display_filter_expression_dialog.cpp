/****************************************************************************
** Meta object code from reading C++ file 'display_filter_expression_dialog.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/display_filter_expression_dialog.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'display_filter_expression_dialog.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_DisplayFilterExpressionDialog_t {
    QByteArrayData data[13];
    char stringdata0[292];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_DisplayFilterExpressionDialog_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_DisplayFilterExpressionDialog_t qt_meta_stringdata_DisplayFilterExpressionDialog = {
    {
QT_MOC_LITERAL(0, 0, 29), // "DisplayFilterExpressionDialog"
QT_MOC_LITERAL(1, 30, 19), // "insertDisplayFilter"
QT_MOC_LITERAL(2, 50, 0), // ""
QT_MOC_LITERAL(3, 51, 6), // "filter"
QT_MOC_LITERAL(4, 58, 8), // "fillTree"
QT_MOC_LITERAL(5, 67, 13), // "updateWidgets"
QT_MOC_LITERAL(6, 81, 39), // "on_fieldTreeWidget_itemSelect..."
QT_MOC_LITERAL(7, 121, 42), // "on_relationListWidget_itemSel..."
QT_MOC_LITERAL(8, 164, 38), // "on_enumListWidget_itemSelecti..."
QT_MOC_LITERAL(9, 203, 29), // "on_searchLineEdit_textChanged"
QT_MOC_LITERAL(10, 233, 9), // "search_re"
QT_MOC_LITERAL(11, 243, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(12, 265, 26) // "on_buttonBox_helpRequested"

    },
    "DisplayFilterExpressionDialog\0"
    "insertDisplayFilter\0\0filter\0fillTree\0"
    "updateWidgets\0on_fieldTreeWidget_itemSelectionChanged\0"
    "on_relationListWidget_itemSelectionChanged\0"
    "on_enumListWidget_itemSelectionChanged\0"
    "on_searchLineEdit_textChanged\0search_re\0"
    "on_buttonBox_accepted\0on_buttonBox_helpRequested"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_DisplayFilterExpressionDialog[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       9,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   59,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       4,    0,   62,    2, 0x08 /* Private */,
       5,    0,   63,    2, 0x08 /* Private */,
       6,    0,   64,    2, 0x08 /* Private */,
       7,    0,   65,    2, 0x08 /* Private */,
       8,    0,   66,    2, 0x08 /* Private */,
       9,    1,   67,    2, 0x08 /* Private */,
      11,    0,   70,    2, 0x08 /* Private */,
      12,    0,   71,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,   10,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void DisplayFilterExpressionDialog::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        DisplayFilterExpressionDialog *_t = static_cast<DisplayFilterExpressionDialog *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->insertDisplayFilter((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->fillTree(); break;
        case 2: _t->updateWidgets(); break;
        case 3: _t->on_fieldTreeWidget_itemSelectionChanged(); break;
        case 4: _t->on_relationListWidget_itemSelectionChanged(); break;
        case 5: _t->on_enumListWidget_itemSelectionChanged(); break;
        case 6: _t->on_searchLineEdit_textChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 7: _t->on_buttonBox_accepted(); break;
        case 8: _t->on_buttonBox_helpRequested(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (DisplayFilterExpressionDialog::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&DisplayFilterExpressionDialog::insertDisplayFilter)) {
                *result = 0;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject DisplayFilterExpressionDialog::staticMetaObject = { {
    &GeometryStateDialog::staticMetaObject,
    qt_meta_stringdata_DisplayFilterExpressionDialog.data,
    qt_meta_data_DisplayFilterExpressionDialog,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *DisplayFilterExpressionDialog::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *DisplayFilterExpressionDialog::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_DisplayFilterExpressionDialog.stringdata0))
        return static_cast<void*>(this);
    return GeometryStateDialog::qt_metacast(_clname);
}

int DisplayFilterExpressionDialog::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = GeometryStateDialog::qt_metacall(_c, _id, _a);
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

// SIGNAL 0
void DisplayFilterExpressionDialog::insertDisplayFilter(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
