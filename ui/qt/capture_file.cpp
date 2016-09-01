/* capture_file.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include "log.h"

#include "epan/epan_dissect.h"

#include "ui/capture.h"

#include <QFileInfo>
#include <QTimer>

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
    file_name_(no_capture_file_),
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

const QString CaptureFile::fileName()
{
    if (isValid()) {
        QFileInfo cfi(QString::fromUtf8(cap_file_->filename));
        file_name_ = cfi.baseName();
    }

    return file_name_;
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
    if (capFile() && capFile()->wth) {
        return wtap_file_tsprec(capFile()->wth);
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

    capture_file->captureEvent(event, cap_session);
}
#endif

void CaptureFile::captureFileEvent(int event, gpointer data)
{
    switch(event) {
    case(cf_cb_file_opened):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Opened");
        cap_file_ = (capture_file *) data;
        fileName();
        emit captureFileOpened();
        break;
    case(cf_cb_file_closing):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        file_state_ = tr(" [closing]");
        emit captureFileClosing();
        break;
    case(cf_cb_file_closed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        file_state_ = tr(" [closed]");
        emit captureFileClosed();
        cap_file_ = NULL;
        file_name_ = no_capture_file_;
        file_state_ = QString();
        break;
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        emit captureFileReadStarted();
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        emit captureFileReadFinished();
        break;
    case(cf_cb_file_reload_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload started");
        emit captureFileReloadStarted();
        break;
    case(cf_cb_file_reload_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload finished");
        emit captureFileReloadFinished();
        break;
    case(cf_cb_file_rescan_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Rescan started");
        emit captureFileRescanStarted();
        break;
    case(cf_cb_file_rescan_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Rescan finished");
        emit captureFileRescanFinished();
        break;
    case(cf_cb_file_retap_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Retap started");
        emit captureFileRetapStarted();
        break;
    case(cf_cb_file_retap_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Retap finished");
        /* Flush any pending tapped packet before emitting captureFileRetapFinished() */
        emit captureFileFlushTapsData();
        emit captureFileRetapFinished();
        break;

    case(cf_cb_file_fast_save_finished):
        // gtk/main.c calls main_cf_cb_file_rescan_finished. Should we do
        // the equivalent?
        break;

    case(cf_cb_packet_selected):
    case(cf_cb_packet_unselected):
    case(cf_cb_field_unselected):
        // GTK+ only. Handled in Qt via signals and slots.
        break;

    case(cf_cb_file_save_started):
    {
        const QString file_path = (const char *) data;
        captureFileSaveStarted(file_path);
        break;
    }
    case(cf_cb_file_save_finished):
        emit captureFileSaveFinished();
        break;
    case(cf_cb_file_save_failed):
        emit captureFileSaveFailed();
        break;
    case(cf_cb_file_save_stopped):
        emit captureFileSaveStopped();
        break;

    case cf_cb_file_export_specified_packets_started:
    case cf_cb_file_export_specified_packets_finished:
    case cf_cb_file_export_specified_packets_failed:
    case cf_cb_file_export_specified_packets_stopped:
        // GTK+ only.
        break;

    default:
        g_warning("CaptureFile::captureFileCallback: event %u unknown", event);
        g_assert_not_reached();
        break;
    }
}

void CaptureFile::captureEvent(int event, capture_session *cap_session)
{
#ifndef HAVE_LIBPCAP
    Q_UNUSED(event)
    Q_UNUSED(cap_session)
#else
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        emit captureCapturePrepared(cap_session);
        cap_file_ = cap_session->cf;
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        emit captureCaptureUpdateStarted(cap_session);
        break;
    case(capture_cb_capture_update_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");
        emit captureCaptureUpdateContinue(cap_session);
        break;
    case(capture_cb_capture_update_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        emit captureCaptureUpdateFinished(cap_session);
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        emit captureCaptureFixedStarted(cap_session);
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        emit captureCaptureFixedContinue(cap_session);
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        emit captureCaptureFixedFinished(cap_session);
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
             * closes the capturing on it's own! */
        emit captureCaptureStopping(cap_session);
        break;
    case(capture_cb_capture_failed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture failed");
        emit captureCaptureFailed(cap_session);
        break;
    default:
        g_warning("main_capture_callback: event %u unknown", event);
    }
#endif // HAVE_LIBPCAP
}

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
