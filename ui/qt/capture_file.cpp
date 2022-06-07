/* capture_file.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "capture_file.h"

/*
 * @file Capture file class
 *
 * Wraps the capture_file struct, cfile global, and callbacks.
 */

#include "globals.h"
capture_file cfile;

#include "file.h"

#include "epan/epan_dissect.h"

#include "ui/capture.h"

#include <QFileInfo>
#include <QTimer>
#include <QDebug>

CaptureEvent::CaptureEvent(Context ctx, EventType evt) :
    _ctx(ctx),
    _evt(evt),
    _session(Q_NULLPTR)
{
}

CaptureEvent::CaptureEvent(Context ctx, EventType evt, QString file) :
    _ctx(ctx),
    _evt(evt),
    _filePath(file),
    _session(Q_NULLPTR)
{
}

CaptureEvent::CaptureEvent(Context ctx, EventType evt, capture_session * session) :
    _ctx(ctx),
    _evt(evt),
    _session(session)
{
}

CaptureEvent::CaptureEvent(const CaptureEvent &ce) :
    _ctx(ce._ctx),
    _evt(ce._evt),
    _filePath(ce._filePath),
    _session(ce._session)
{
}

CaptureEvent::Context CaptureEvent::captureContext() const
{ return _ctx; }

CaptureEvent::EventType CaptureEvent::eventType() const
{ return _evt; }

QString CaptureEvent::filePath() const
{ return _filePath; }

capture_session * CaptureEvent::capSession() const
{ return _session; }

// To do:
// - Add getters and (if needed) setters:
//   - Full filename
//   - Capture state (stopped, prepared, running).
// - Call common_create_progress_dlg. This would let us manage the stop
//   flag here as well as emit progress signals.

QString CaptureFile::no_capture_file_ = QObject::tr("[no capture file]");

CaptureFile::CaptureFile(QObject *parent, capture_file *cap_file) :
    QObject(parent),
    cap_file_(cap_file),
    file_state_(QString())
{
#ifdef HAVE_LIBPCAP
    capture_callback_add(captureCallback, (gpointer) this);
#endif
    cf_callback_add(captureFileCallback, (gpointer) this);
}

CaptureFile::~CaptureFile()
{
    cf_callback_remove(captureFileCallback, this);
}

bool CaptureFile::isValid() const
{
    if (cap_file_ && cap_file_->state != FILE_CLOSED) { // XXX FILE_READ_IN_PROGRESS as well?
        return true;
    }
    return false;
}

int CaptureFile::currentRow()
{
    if (isValid())
        return cap_file_->current_row;
    return -1;
}

const QString CaptureFile::filePath()
{
    QString path;

    if (isValid()) {
        //
        // Sadly, some UN*Xes don't necessarily use UTF-8
        // for their file names, so we have to map the
        // file path to UTF-8.  If that fails, we're somewhat
        // stuck.
        //
        char *utf8_filename = g_filename_to_utf8(cap_file_->filename,
                                                 -1,
                                                 NULL,
                                                 NULL,
                                                 NULL);
        if (utf8_filename) {
            path = QString::fromUtf8(utf8_filename);
            g_free(utf8_filename);
        } else {
            // So what the heck else can we do here?
            path = QString();
        }
    } else {
        path = QString();
    }
    return path;
}

const QString CaptureFile::fileName()
{
    QString path, name;

    path = filePath();
    if (!path.isEmpty()) {
        QFileInfo cfi(path);
        name = cfi.fileName();
    } else {
        name = QString();
    }

    return name;
}

const QString CaptureFile::fileBaseName()
{
    QString baseName;

    if (isValid()) {
        char *basename = cf_get_basename(cap_file_);
        baseName = basename;
        g_free(basename);
    } else {
        baseName = QString();
    }
    return baseName;
}

const QString CaptureFile::fileDisplayName()
{
    QString displayName;

    if (isValid()) {
        char *display_name = cf_get_display_name(cap_file_);
        displayName = display_name;
        g_free(display_name);
    } else {
        displayName = QString();
    }
    return displayName;
}

const QString CaptureFile::fileTitle()
{
    QString title;

    if (isValid()) {
        title = fileDisplayName() + file_state_;
    } else {
        title = no_capture_file_;
    }
    return title;
}

struct _packet_info *CaptureFile::packetInfo()
{
    if (capFile() && capFile()->edt) {
        return &(capFile()->edt->pi);
    }
    return NULL;
}

int CaptureFile::timestampPrecision()
{
    if (capFile() && capFile()->provider.wth) {
        return wtap_file_tsprec(capFile()->provider.wth);
    }
    return WTAP_TSPREC_UNKNOWN;
}

void CaptureFile::retapPackets()
{
    if (cap_file_) {
        cf_retap_packets(cap_file_);
    }
}

void CaptureFile::delayedRetapPackets()
{
    QTimer::singleShot(0, this, SLOT(retapPackets()));
}

void CaptureFile::reload()
{
    if (cap_file_ && cap_file_->state == FILE_READ_DONE) {
        cf_reload(cap_file_);
    }
}

void CaptureFile::stopLoading()
{
    setCaptureStopFlag(true);
}

QString CaptureFile::displayFilter() const
{
    if (isValid())
        return QString(cap_file_->dfilter);
    return QString();
}

capture_file *CaptureFile::globalCapFile()
{
    return &cfile;
}

gpointer CaptureFile::window()
{
    if (cap_file_) return cap_file_->window;
    return NULL;
}

void CaptureFile::setCaptureStopFlag(bool stop_flag)
{
    if (cap_file_) cap_file_->stop_flag = stop_flag;
}

void CaptureFile::captureFileCallback(gint event, gpointer data, gpointer user_data)
{
    CaptureFile *capture_file = static_cast<CaptureFile *>(user_data);
    if (!capture_file) return;

    capture_file->captureFileEvent(event, data);
}

#ifdef HAVE_LIBPCAP
void CaptureFile::captureCallback(gint event, capture_session *cap_session, gpointer user_data)
{
    CaptureFile *capture_file = static_cast<CaptureFile *>(user_data);
    if (!capture_file) return;

    capture_file->captureSessionEvent(event, cap_session);
}
#endif

void CaptureFile::captureFileEvent(int event, gpointer data)
{
    switch(event) {
    case(cf_cb_file_opened):
        cap_file_ = (capture_file *) data;
        emit captureEvent(CaptureEvent(CaptureEvent::File, CaptureEvent::Opened));
        break;
    case(cf_cb_file_closing):
        file_state_ = tr(" [closing]");
        emit captureEvent(CaptureEvent(CaptureEvent::File, CaptureEvent::Closing));
        break;
    case(cf_cb_file_closed):
        file_state_ = tr(" [closed]");
        emit captureEvent(CaptureEvent(CaptureEvent::File, CaptureEvent::Closed));
        cap_file_ = NULL;
        file_state_ = QString();
        break;
    case(cf_cb_file_read_started):
        emit captureEvent(CaptureEvent(CaptureEvent::File, CaptureEvent::Started));
        break;
    case(cf_cb_file_read_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::File, CaptureEvent::Finished));
        break;
    case(cf_cb_file_reload_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Reload, CaptureEvent::Started));
        break;
    case(cf_cb_file_reload_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Reload, CaptureEvent::Finished));
        break;
    case(cf_cb_file_rescan_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Rescan, CaptureEvent::Started));
        break;
    case(cf_cb_file_rescan_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Rescan, CaptureEvent::Finished));
        break;
    case(cf_cb_file_retap_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Retap, CaptureEvent::Started));
        break;
    case(cf_cb_file_retap_finished):
        /* Flush any pending tapped packet before emitting captureFileRetapFinished() */
        emit captureEvent(CaptureEvent(CaptureEvent::Retap, CaptureEvent::Finished));
        emit captureEvent(CaptureEvent(CaptureEvent::Retap, CaptureEvent::Flushed));
        break;
    case(cf_cb_file_merge_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Merge, CaptureEvent::Started));
        break;
    case(cf_cb_file_merge_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Merge, CaptureEvent::Finished));
        break;

    case(cf_cb_file_fast_save_finished):
        // gtk/main.c calls main_cf_cb_file_rescan_finished. Should we do
        // the equivalent?
        break;

    case(cf_cb_file_save_started):
    {
        emit captureEvent(CaptureEvent(CaptureEvent::Save, CaptureEvent::Started, QString((const char *)data)));
        break;
    }
    case(cf_cb_file_save_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Save, CaptureEvent::Finished));
        break;
    case(cf_cb_file_save_failed):
        emit captureEvent(CaptureEvent(CaptureEvent::Save, CaptureEvent::Failed));
        break;
    case(cf_cb_file_save_stopped):
        emit captureEvent(CaptureEvent(CaptureEvent::Save, CaptureEvent::Stopped));
        break;

    default:
        qWarning() << "CaptureFile::captureFileCallback: event " << event << " unknown";
        Q_ASSERT(false);
        break;
    }
}

#ifdef HAVE_LIBPCAP
void CaptureFile::captureSessionEvent(int event, capture_session *cap_session)
{
    switch(event) {
    case(capture_cb_capture_prepared):
        emit captureEvent(CaptureEvent(CaptureEvent::Capture, CaptureEvent::Prepared, cap_session));
        cap_file_ = cap_session->cf;
        break;
    case(capture_cb_capture_update_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Update, CaptureEvent::Started, cap_session));
        break;
    case(capture_cb_capture_update_continue):
        emit captureEvent(CaptureEvent(CaptureEvent::Update, CaptureEvent::Continued, cap_session));
        break;
    case(capture_cb_capture_update_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Update, CaptureEvent::Finished, cap_session));
        break;
    case(capture_cb_capture_fixed_started):
        emit captureEvent(CaptureEvent(CaptureEvent::Fixed, CaptureEvent::Started, cap_session));
        break;
    case(capture_cb_capture_fixed_continue):
        emit captureEvent(CaptureEvent(CaptureEvent::Fixed, CaptureEvent::Continued, cap_session));
        break;
    case(capture_cb_capture_fixed_finished):
        emit captureEvent(CaptureEvent(CaptureEvent::Fixed, CaptureEvent::Finished, cap_session));
        break;
    case(capture_cb_capture_stopping):
        /* Beware: this state won't be called, if the capture child
             * closes the capturing on it's own! */
        emit captureEvent(CaptureEvent(CaptureEvent::Capture, CaptureEvent::Stopping, cap_session));
        break;
    case(capture_cb_capture_failed):
        emit captureEvent(CaptureEvent(CaptureEvent::Capture, CaptureEvent::Failed, cap_session));
        break;
    default:
        qWarning() << "main_capture_callback: event " << event << " unknown";
    }
}
#endif // HAVE_LIBPCAP
