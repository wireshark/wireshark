/* wireshark_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "cfile.h"

#include <epan/packet.h>
#include <epan/tap.h>

#include "main_application.h"
#include "wireshark_dialog.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include "ui/recent.h"
#include "ui/ws_ui_util.h"

#include <QMessageBox>


// To do:
// - Use a dynamic property + Q_PROPERTY for the subtitle.
// - Make our nested event loop more robust. See tryDeleteLater for details.

WiresharkDialog::WiresharkDialog(QWidget &parent, CaptureFile &capture_file) :
    GeometryStateDialog(&parent, Qt::Window),
    cap_file_(capture_file),
    file_closed_(false),
    retap_depth_(0),
    dialog_closed_(false)
{
    setWindowIcon(mainApp->normalIcon());
    setWindowSubtitle(QString());

    connect(&cap_file_, &CaptureFile::captureEvent, this, &WiresharkDialog::captureEvent);
}

void WiresharkDialog::accept()
{
    QDialog::accept();
    dialogCleanup(true);
}

// XXX Should we do this in WiresharkDialog?
void WiresharkDialog::reject()
{
    QDialog::reject();
    dialogCleanup(true);
}

void WiresharkDialog::setWindowSubtitle(const QString &subtitle)
{
    subtitle_ = subtitle;

    QString title = mainApp->windowTitleString(QStringList() << subtitle_ << cap_file_.fileTitle());
    QDialog::setWindowTitle(title);
}

// See if we can destroy ourselves. The user may have clicked "Close" while
// we were deep in the bowels of a routine that retaps packets. Track our
// tapping state using retap_depth_ and our closed state using dialog_closed_.
//
// The Delta Object Rules page on nested event loops:
//
//    https://jblog.andbit.net/2007/04/28/delta-object-rules/
//
// effectively says "don't do that." However, we don't really have a choice
// if we want to have a usable application that retaps packets.

void WiresharkDialog::dialogCleanup(bool closeDialog)
{
    if (closeDialog)
    {
        // Cancel any taps in progress?
        // cap_file_.setCaptureStopFlag();
        removeTapListeners();
        dialog_closed_ = true;
    }

    if (retap_depth_ < 1 && dialog_closed_) {
        disconnect();
        deleteLater();
    }
}

void WiresharkDialog::updateWidgets()
{
    setWindowSubtitle(subtitle_);
}

bool WiresharkDialog::registerTapListener(const char *tap_name, void *tap_data, const char *filter, guint flags, tap_reset_cb tap_reset, tap_packet_cb tap_packet, tap_draw_cb tap_draw)
{
    GString *error_string = register_tap_listener(tap_name, tap_data, filter, flags,
                                                  tap_reset, tap_packet, tap_draw, NULL);
    if (error_string) {
        QMessageBox::warning(this, tr("Failed to attach to tap \"%1\"").arg(tap_name),
                             error_string->str);
        g_string_free(error_string, TRUE);
        return false;
    }

    tap_listeners_ << tap_data;
    return true;
}

void WiresharkDialog::captureEvent(CaptureEvent e)
{
    switch (e.captureContext())
    {
    case CaptureEvent::Retap:
        switch (e.eventType())
        {
        case CaptureEvent::Started:
            beginRetapPackets();
            break;
        case CaptureEvent::Finished:
            endRetapPackets();
            break;
        default:
            break;
        }
        break;
    case CaptureEvent::File:
        switch (e.eventType())
        {
        case CaptureEvent::Closing:
            captureFileClosing();
            break;
        case CaptureEvent::Closed:
            file_closed_ = true;
            captureFileClosed();
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

}

void WiresharkDialog::beginRetapPackets()
{
    retap_depth_++;
}

void WiresharkDialog::endRetapPackets()
{
    retap_depth_--;
    dialogCleanup();
}

void WiresharkDialog::removeTapListeners()
{
    while (!tap_listeners_.isEmpty()) {
        remove_tap_listener(tap_listeners_.takeFirst());
    }
}

void WiresharkDialog::captureFileClosing()
{
    removeTapListeners();
    updateWidgets();
}

void WiresharkDialog::captureFileClosed()
{
    updateWidgets();
}
