/****************************************************************************
** Meta object code from reading C++ file 'address_editor_frame.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/address_editor_frame.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'address_editor_frame.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_AddressEditorFrame_t {
    QByteArrayData data[17];
    char stringdata0[312];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_AddressEditorFrame_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_AddressEditorFrame_t qt_meta_stringdata_AddressEditorFrame = {
    {
QT_MOC_LITERAL(0, 0, 18), // "AddressEditorFrame"
QT_MOC_LITERAL(1, 19, 29), // "showNameResolutionPreferences"
QT_MOC_LITERAL(2, 49, 0), // ""
QT_MOC_LITERAL(3, 50, 11), // "module_name"
QT_MOC_LITERAL(4, 62, 17), // "editAddressStatus"
QT_MOC_LITERAL(5, 80, 6), // "status"
QT_MOC_LITERAL(6, 87, 16), // "redissectPackets"
QT_MOC_LITERAL(7, 104, 13), // "editAddresses"
QT_MOC_LITERAL(8, 118, 12), // "CaptureFile&"
QT_MOC_LITERAL(9, 131, 2), // "cf"
QT_MOC_LITERAL(10, 134, 6), // "column"
QT_MOC_LITERAL(11, 141, 13), // "updateWidgets"
QT_MOC_LITERAL(12, 155, 46), // "on_nameResolutionPreferencesT..."
QT_MOC_LITERAL(13, 202, 38), // "on_addressComboBox_currentInd..."
QT_MOC_LITERAL(14, 241, 26), // "on_nameLineEdit_textEdited"
QT_MOC_LITERAL(15, 268, 21), // "on_buttonBox_accepted"
QT_MOC_LITERAL(16, 290, 21) // "on_buttonBox_rejected"

    },
    "AddressEditorFrame\0showNameResolutionPreferences\0"
    "\0module_name\0editAddressStatus\0status\0"
    "redissectPackets\0editAddresses\0"
    "CaptureFile&\0cf\0column\0updateWidgets\0"
    "on_nameResolutionPreferencesToolButton_clicked\0"
    "on_addressComboBox_currentIndexChanged\0"
    "on_nameLineEdit_textEdited\0"
    "on_buttonBox_accepted\0on_buttonBox_rejected"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_AddressEditorFrame[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       3,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   69,    2, 0x06 /* Public */,
       4,    1,   72,    2, 0x06 /* Public */,
       6,    0,   75,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       7,    2,   76,    2, 0x0a /* Public */,
       7,    1,   81,    2, 0x2a /* Public | MethodCloned */,
      11,    0,   84,    2, 0x08 /* Private */,
      12,    0,   85,    2, 0x08 /* Private */,
      13,    1,   86,    2, 0x08 /* Private */,
      14,    1,   89,    2, 0x08 /* Private */,
      15,    0,   92,    2, 0x08 /* Private */,
      16,    0,   93,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void, 0x80000000 | 8, QMetaType::Int,    9,   10,
    QMetaType::Void, 0x80000000 | 8,    9,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void, QMetaType::QString,    2,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void AddressEditorFrame::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        AddressEditorFrame *_t = static_cast<AddressEditorFrame *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->showNameResolutionPreferences((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 1: _t->editAddressStatus((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 2: _t->redissectPackets(); break;
        case 3: _t->editAddresses((*reinterpret_cast< CaptureFile(*)>(_a[1])),(*reinterpret_cast< int(*)>(_a[2]))); break;
        case 4: _t->editAddresses((*reinterpret_cast< CaptureFile(*)>(_a[1]))); break;
        case 5: _t->updateWidgets(); break;
        case 6: _t->on_nameResolutionPreferencesToolButton_clicked(); break;
        case 7: _t->on_addressComboBox_currentIndexChanged((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 8: _t->on_nameLineEdit_textEdited((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 9: _t->on_buttonBox_accepted(); break;
        case 10: _t->on_buttonBox_rejected(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (AddressEditorFrame::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&AddressEditorFrame::showNameResolutionPreferences)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (AddressEditorFrame::*)(const QString & );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&AddressEditorFrame::editAddressStatus)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (AddressEditorFrame::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&AddressEditorFrame::redissectPackets)) {
                *result = 2;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject AddressEditorFrame::staticMetaObject = { {
    &AccordionFrame::staticMetaObject,
    qt_meta_stringdata_AddressEditorFrame.data,
    qt_meta_data_AddressEditorFrame,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *AddressEditorFrame::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *AddressEditorFrame::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_AddressEditorFrame.stringdata0))
        return static_cast<void*>(this);
    return AccordionFrame::qt_metacast(_clname);
}

int AddressEditorFrame::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = AccordionFrame::qt_metacall(_c, _id, _a);
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
void AddressEditorFrame::showNameResolutionPreferences(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void AddressEditorFrame::editAddressStatus(const QString & _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void AddressEditorFrame::redissectPackets()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
