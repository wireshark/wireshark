/****************************************************************************
** Meta object code from reading C++ file 'rtp_audio_stream.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.0)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../../../../ui/qt/rtp_audio_stream.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'rtp_audio_stream.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.0. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_RtpAudioStream_t {
    QByteArrayData data[14];
    char stringdata0[171];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_RtpAudioStream_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_RtpAudioStream_t qt_meta_stringdata_RtpAudioStream = {
    {
QT_MOC_LITERAL(0, 0, 14), // "RtpAudioStream"
QT_MOC_LITERAL(1, 15, 14), // "startedPlaying"
QT_MOC_LITERAL(2, 30, 0), // ""
QT_MOC_LITERAL(3, 31, 13), // "processedSecs"
QT_MOC_LITERAL(4, 45, 4), // "secs"
QT_MOC_LITERAL(5, 50, 13), // "playbackError"
QT_MOC_LITERAL(6, 64, 9), // "error_msg"
QT_MOC_LITERAL(7, 74, 15), // "finishedPlaying"
QT_MOC_LITERAL(8, 90, 12), // "startPlaying"
QT_MOC_LITERAL(9, 103, 11), // "stopPlaying"
QT_MOC_LITERAL(10, 115, 18), // "outputStateChanged"
QT_MOC_LITERAL(11, 134, 13), // "QAudio::State"
QT_MOC_LITERAL(12, 148, 9), // "new_state"
QT_MOC_LITERAL(13, 158, 12) // "outputNotify"

    },
    "RtpAudioStream\0startedPlaying\0\0"
    "processedSecs\0secs\0playbackError\0"
    "error_msg\0finishedPlaying\0startPlaying\0"
    "stopPlaying\0outputStateChanged\0"
    "QAudio::State\0new_state\0outputNotify"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_RtpAudioStream[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    0,   54,    2, 0x06 /* Public */,
       3,    1,   55,    2, 0x06 /* Public */,
       5,    1,   58,    2, 0x06 /* Public */,
       7,    0,   61,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    0,   62,    2, 0x0a /* Public */,
       9,    0,   63,    2, 0x0a /* Public */,
      10,    1,   64,    2, 0x08 /* Private */,
      13,    0,   67,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void,
    QMetaType::Void, QMetaType::Double,    4,
    QMetaType::Void, QMetaType::QString,    6,
    QMetaType::Void,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, 0x80000000 | 11,   12,
    QMetaType::Void,

       0        // eod
};

void RtpAudioStream::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        RtpAudioStream *_t = static_cast<RtpAudioStream *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->startedPlaying(); break;
        case 1: _t->processedSecs((*reinterpret_cast< double(*)>(_a[1]))); break;
        case 2: _t->playbackError((*reinterpret_cast< const QString(*)>(_a[1]))); break;
        case 3: _t->finishedPlaying(); break;
        case 4: _t->startPlaying(); break;
        case 5: _t->stopPlaying(); break;
        case 6: _t->outputStateChanged((*reinterpret_cast< QAudio::State(*)>(_a[1]))); break;
        case 7: _t->outputNotify(); break;
        default: ;
        }
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        switch (_id) {
        default: *reinterpret_cast<int*>(_a[0]) = -1; break;
        case 6:
            switch (*reinterpret_cast<int*>(_a[1])) {
            default: *reinterpret_cast<int*>(_a[0]) = -1; break;
            case 0:
                *reinterpret_cast<int*>(_a[0]) = qRegisterMetaType< QAudio::State >(); break;
            }
            break;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (RtpAudioStream::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpAudioStream::startedPlaying)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (RtpAudioStream::*)(double );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpAudioStream::processedSecs)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (RtpAudioStream::*)(const QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpAudioStream::playbackError)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (RtpAudioStream::*)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&RtpAudioStream::finishedPlaying)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject RtpAudioStream::staticMetaObject = { {
    &QObject::staticMetaObject,
    qt_meta_stringdata_RtpAudioStream.data,
    qt_meta_data_RtpAudioStream,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *RtpAudioStream::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *RtpAudioStream::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_RtpAudioStream.stringdata0))
        return static_cast<void*>(this);
    return QObject::qt_metacast(_clname);
}

int RtpAudioStream::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    }
    return _id;
}

// SIGNAL 0
void RtpAudioStream::startedPlaying()
{
    QMetaObject::activate(this, &staticMetaObject, 0, nullptr);
}

// SIGNAL 1
void RtpAudioStream::processedSecs(double _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void RtpAudioStream::playbackError(const QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void RtpAudioStream::finishedPlaying()
{
    QMetaObject::activate(this, &staticMetaObject, 3, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
