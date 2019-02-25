/****************************************************************************
** Meta object code from reading C++ file 'column_preferences_frame.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/column_preferences_frame.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'column_preferences_frame.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_ColumnPreferencesFrame_t {
    QByteArrayData data[18];
    char stringdata0[358];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_ColumnPreferencesFrame_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_ColumnPreferencesFrame_t qt_meta_stringdata_ColumnPreferencesFrame = {
    {
QT_MOC_LITERAL(0, 0, 22), // "ColumnPreferencesFrame"
QT_MOC_LITERAL(1, 23, 13), // "updateWidgets"
QT_MOC_LITERAL(2, 37, 0), // ""
QT_MOC_LITERAL(3, 38, 38), // "on_columnTreeWidget_currentIt..."
QT_MOC_LITERAL(4, 77, 16), // "QTreeWidgetItem*"
QT_MOC_LITERAL(5, 94, 8), // "previous"
QT_MOC_LITERAL(6, 103, 33), // "on_columnTreeWidget_itemActiv..."
QT_MOC_LITERAL(7, 137, 4), // "item"
QT_MOC_LITERAL(8, 142, 6), // "column"
QT_MOC_LITERAL(9, 149, 17), // "lineEditDestroyed"
QT_MOC_LITERAL(10, 167, 14), // "comboDestroyed"
QT_MOC_LITERAL(11, 182, 26), // "columnTitleEditingFinished"
QT_MOC_LITERAL(12, 209, 29), // "columnTypeCurrentIndexChanged"
QT_MOC_LITERAL(13, 239, 5), // "index"
QT_MOC_LITERAL(14, 245, 27), // "customFieldsEditingFinished"
QT_MOC_LITERAL(15, 273, 31), // "customOccurrenceEditingFinished"
QT_MOC_LITERAL(16, 305, 24), // "on_newToolButton_clicked"
QT_MOC_LITERAL(17, 330, 27) // "on_deleteToolButton_clicked"

    },
    "ColumnPreferencesFrame\0updateWidgets\0"
    "\0on_columnTreeWidget_currentItemChanged\0"
    "QTreeWidgetItem*\0previous\0"
    "on_columnTreeWidget_itemActivated\0"
    "item\0column\0lineEditDestroyed\0"
    "comboDestroyed\0columnTitleEditingFinished\0"
    "columnTypeCurrentIndexChanged\0index\0"
    "customFieldsEditingFinished\0"
    "customOccurrenceEditingFinished\0"
    "on_newToolButton_clicked\0"
    "on_deleteToolButton_clicked"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_ColumnPreferencesFrame[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: name, argc, parameters, tag, flags
       1,    0,   69,    2, 0x08 /* Private */,
       3,    2,   70,    2, 0x08 /* Private */,
       6,    2,   75,    2, 0x08 /* Private */,
       9,    0,   80,    2, 0x08 /* Private */,
      10,    0,   81,    2, 0x08 /* Private */,
      11,    0,   82,    2, 0x08 /* Private */,
      12,    1,   83,    2, 0x08 /* Private */,
      14,    0,   86,    2, 0x08 /* Private */,
      15,    0,   87,    2, 0x08 /* Private */,
      16,    0,   88,    2, 0x08 /* Private */,
      17,    0,   89,    2, 0x08 /* Private */,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 4, 0x80000000 | 4,    2,    5,
    QMetaType::Void, 0x80000000 | 4, QMetaType::Int,    7,    8,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Int,   13,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void ColumnPreferencesFrame::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        ColumnPreferencesFrame *_t = static_cast<ColumnPreferencesFrame *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->updateWidgets(); break;
        case 1: _t->on_columnTreeWidget_currentItemChanged((*reinterpret_cast< QTreeWidgetItem*(*)>(_a[1])),(*reinterpret_cast< QTreeWidgetItem*(*)>(_a[2]))); break;
        case 2: _t->on_columnTreeWidget_itemActivated((*reinterpret_cast< QTreeWidgetItem*(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 3: _t->lineEditDestroyed(); break;
        case 4: _t->comboDestroyed(); break;
        case 5: _t->columnTitleEditingFinished(); break;
        case 6: _t->columnTypeCurrentIndexChanged((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 7: _t->customFieldsEditingFinished(); break;
        case 8: _t->customOccurrenceEditingFinished(); break;
        case 9: _t->on_newToolButton_clicked(); break;
        case 10: _t->on_deleteToolButton_clicked(); break;
        default: ;
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject ColumnPreferencesFrame::staticMetaObject = { {
    &QFrame::staticMetaObject,
    qt_meta_stringdata_ColumnPreferencesFrame.data,
    qt_meta_data_ColumnPreferencesFrame,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *ColumnPreferencesFrame::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *ColumnPreferencesFrame::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_ColumnPreferencesFrame.stringdata0))
        return static_cast<void*>(this);
    return QFrame::qt_metacast(_clname);
}

int ColumnPreferencesFrame::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QFrame::qt_metacall(_c, _id, _a);
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
QT_WARNING_POP
QT_END_MOC_NAMESPACE
