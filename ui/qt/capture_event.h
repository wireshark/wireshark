/** @file
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
#include <QString>

typedef struct _capture_session capture_session;

struct _packet_info;

/**
 * @brief Represents an event occurring during a capture or file operation.
 */
class CaptureEvent
{
public:
    /**
     * @brief Defines the operational context of the event.
     */
    enum Context {
#ifdef HAVE_LIBPCAP
        Capture =  0x0001,           /**< A live capture context. */
        Update =   0x0100 | Capture, /**< An update during a live capture context. */
        Fixed =    0x0200 | Capture, /**< A fixed capture context. */
#endif
        File =     0x0002,           /**< A file operation context. */
        Reload =   0x0100 | File,    /**< A file reload context. */
        Rescan =   0x0200 | File,    /**< A file rescan context. */
        Save =     0x0400 | File,    /**< A file save context. */
        Retap =    0x0800 | File,    /**< A file retap context. */
        Merge =    0x1000 | File     /**< A file merge context. */
    };

    /**
     * @brief Defines the specific type of event.
     */
    enum EventType {
        Opened      = 0x0001,        /**< The capture or file was opened. */
        Started     = 0x0002,        /**< The operation has started. */
        Finished    = 0x0004,        /**< The operation has finished. */
        Closing     = 0x0008,        /**< The capture or file is currently closing. */
        Closed      = 0x0010,        /**< The capture or file was closed. */
        Failed      = 0x0020,        /**< The operation failed. */
        Stopped     = 0x0040,        /**< The operation was stopped. */
        Flushed     = 0x0080,        /**< The data was flushed. */
        Prepared    = 0x0100,        /**< The operation was prepared. */
        Continued   = 0x0200,        /**< The operation has continued. */
        Stopping    = 0x0400         /**< The operation is currently stopping. */
    };

    /**
     * @brief Constructs a new CaptureEvent with a specific context and event type.
     * @param ctx The context in which the event occurred.
     * @param evt The type of event.
     */
    CaptureEvent(Context ctx, EventType evt);

    /**
     * @brief Constructs a new CaptureEvent with an associated file path.
     * @param ctx The context in which the event occurred.
     * @param evt The type of event.
     * @param file The file path associated with the event.
     */
    CaptureEvent(Context ctx, EventType evt, QString file);

    /**
     * @brief Constructs a new CaptureEvent with an associated capture session.
     * @param ctx The context in which the event occurred.
     * @param evt The type of event.
     * @param session The capture session associated with the event.
     */
    CaptureEvent(Context ctx, EventType evt, capture_session * session);

    /**
     * @brief Copy constructor for CaptureEvent.
     * @param ce The CaptureEvent to copy.
     */
    CaptureEvent(const CaptureEvent &ce);

    /**
     * @brief Retrieves the context of the capture event.
     * @return The context of the event.
     */
    Context captureContext() const;

    /**
     * @brief Retrieves the type of the capture event.
     * @return The event type.
     */
    EventType eventType() const;

    /**
     * @brief Retrieves the associated file path.
     * @return The file path string.
     */
    QString filePath() const;

    /**
     * @brief Retrieves the associated capture session.
     * @return A pointer to the capture session.
     */
    capture_session * capSession() const;

private:
    /** The context of the capture event. */
    Context _ctx;

    /** The type of the capture event. */
    EventType _evt;

    /** The file path associated with the event, if applicable. */
    QString _filePath;

    /** Pointer to the associated capture session, if applicable. */
    capture_session * _session;
};

#endif // CAPTURE_EVENT_H
