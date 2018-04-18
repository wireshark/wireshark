/* capture_event.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_EVENT_H
#define CAPTURE_EVENT_H

#include <QEvent>

typedef struct _capture_session capture_session;

struct _packet_info;

class CaptureEvent
{
public:
    enum Context {
#ifdef HAVE_LIBPCAP
        Capture =  0x0001,
        Update =   0x0100 | Capture,
        Fixed =    0x0200 | Capture,
#endif
        File =     0x0002,
        Reload =   0x0100 | File,
        Rescan =   0x0200 | File,
        Save =     0x0400 | File,
        Retap =    0x0800 | File,
        Merge =    0x1000 | File
    };

    enum EventType {
        Opened      = 0x0001,
        Started     = 0x0002,
        Finished    = 0x0004,
        Closing     = 0x0008,
        Closed      = 0x0010,
        Failed      = 0x0020,
        Stopped     = 0x0040,
        Flushed     = 0x0080,
        Prepared    = 0x0100,
        Continued   = 0x0200,
        Stopping    = 0x0400
    };

    CaptureEvent(Context ctx, EventType evt);
    CaptureEvent(Context ctx, EventType evt, QString file);
    CaptureEvent(Context ctx, EventType evt, capture_session * session);

    CaptureEvent(const CaptureEvent &ce);

    Context captureContext() const;
    EventType eventType() const;
    QString filePath() const;
    capture_session * capSession() const;

private:
    Context _ctx;
    EventType _evt;
    QString _filePath;
    capture_session * _session;
};

#endif // CAPTURE_EVENT_H

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
