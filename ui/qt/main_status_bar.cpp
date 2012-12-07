/* main_status_bar.cpp
 *
 * $Id$
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

#include "config.h"

#include <glib.h>

#include "main_status_bar.h"

#include "epan/expert.h"

#include "ui/main_statusbar.h"
#include "ui/utf8_entities.h"

#include <QSplitter>
#include <QHBoxLayout>

#include "tango_colors.h"

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE tr("Ready to load or capture")
#else
#define DEF_READY_MESSAGE tr("Ready to load file")
#endif

// XXX - The GTK+ code assigns priorities to these and pushes/pops accordingly.

enum StatusContext {
    STATUS_CTX_MAIN,
    STATUS_CTX_FILE,
    STATUS_CTX_FIELD,
    STATUS_CTX_FILTER,
    STATUS_CTX_TEMPORARY
};

// If we ever add support for multiple windows this will need to be replaced.
// See also: main_window.cpp
static MainStatusBar *cur_main_status_bar_ = NULL;

/*
 * Push a formatted temporary message onto the statusbar.
 */
void
statusbar_push_temporary_msg(const gchar *msg_format, ...)
{
    va_list ap;
    gchar *msg;
    QString pushMsg;

    if (!cur_main_status_bar_) return;

    va_start(ap, msg_format);
    msg = g_strdup_vprintf(msg_format, ap);
    va_end(ap);

    pushMsg.fromUtf8(msg);
    g_free(msg);

    cur_main_status_bar_->pushTemporaryStatus(pushMsg);
}

/*
 * Update the packets statusbar to the current values
 */
void
packets_bar_update(void)
{
    if (!cur_main_status_bar_) return;

    cur_main_status_bar_->updateCaptureStatistics(NULL);
}

MainStatusBar::MainStatusBar(QWidget *parent) :
    QStatusBar(parent),
    cap_file_(NULL)
{
    QSplitter *splitter = new QSplitter(this);
    QString ready_msg(DEF_READY_MESSAGE);
    QWidget *info_progress = new QWidget(this);
    QHBoxLayout *info_progress_hb = new QHBoxLayout(info_progress);

#if defined(Q_WS_WIN)
    // Handles are the same color as widgets, at least on Windows 7.
    splitter->setHandleWidth(3);
    splitter->setStyleSheet(QString(
                                "QSplitter::handle {"
                                "  border-left: 1px solid palette(mid);"
                                "  border-right: 1px solid palette(mid);"
                                "}"
                                ));
#elif defined(Q_WS_MAC)
    expert_status_.setAttribute(Qt::WA_MacSmallSize, true);
#endif

    expert_status_.setTextFormat(Qt::RichText);
    expert_status_.hide();

    // XXX Add the comment icon

    info_progress_hb->setContentsMargins(0, 0, 0, 0);

    info_status_.setTemporaryContext(STATUS_CTX_TEMPORARY);

    info_progress_hb->addWidget(&expert_status_);
    info_progress_hb->addWidget(&info_status_);
    info_progress_hb->addWidget(&progress_bar_);
    info_progress_hb->addStretch(10);

    splitter->addWidget(info_progress);
    splitter->addWidget(&packet_status_);
    splitter->addWidget(&profile_status_);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 3);
    splitter->setStretchFactor(2, 1);

    addWidget(splitter, 1);

    cur_main_status_bar_ = this;

    splitter->hide();
    info_status_.pushText(ready_msg, STATUS_CTX_MAIN);
    packets_bar_update();

    connect(wsApp, SIGNAL(appInitialized()), splitter, SLOT(show()));
    connect(&info_status_, SIGNAL(toggleTemporaryFlash(bool)),
            this, SLOT(toggleBackground(bool)));
    connect(wsApp, SIGNAL(captureCaptureUpdateContinue(capture_options*)),
            this, SLOT(updateCaptureStatistics(capture_options*)));
}

void MainStatusBar::showExpert() {
    expertUpdate();
}

void MainStatusBar::hideExpert() {
    expert_status_.hide();
}

void MainStatusBar::expertUpdate() {
    QString imgText = "<img src=\":/expert/expert_";
    QString ttText = tr(" is the highest expert info level");

    switch(expert_get_highest_severity()) {
    case(PI_ERROR):
        imgText.append("error");
        ttText.prepend(tr("ERROR"));
        break;
    case(PI_WARN):
        imgText.append("warn");
        ttText.prepend(tr("WARNING"));
        break;
    case(PI_NOTE):
        imgText.append("note");
        ttText.prepend(tr("NOTE"));
        break;
    case(PI_CHAT):
        imgText.append("chat");
        ttText.prepend(tr("CHAT"));
        break;
//    case(PI_COMMENT):
//        m_expertStatus.setText("<img src=\":/expert/expert_comment.png\"></img>");
//        break;
    default:
        imgText.append("none");
        ttText = tr("No expert info");
        break;
    }

    imgText.append(".png\"></img>");
    expert_status_.setText(imgText);
    expert_status_.setToolTip(ttText);
    expert_status_.show();
}

void MainStatusBar::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
}

void MainStatusBar::pushTemporaryStatus(QString &message) {
    info_status_.pushText(message, STATUS_CTX_TEMPORARY);
}

void MainStatusBar::popTemporaryStatus() {
    info_status_.popText(STATUS_CTX_TEMPORARY);
}

void MainStatusBar::pushFileStatus(QString &message) {
    info_status_.pushText(message, STATUS_CTX_FILE);
    expertUpdate();
}

void MainStatusBar::popFileStatus() {
    info_status_.popText(STATUS_CTX_FILE);
}

void MainStatusBar::pushFieldStatus(QString &message) {
    if (message.isNull()) {
        popFieldStatus();
    } else {
        info_status_.pushText(message, STATUS_CTX_FIELD);
    }
}

void MainStatusBar::popFieldStatus() {
    info_status_.popText(STATUS_CTX_FIELD);
}

void MainStatusBar::pushFilterStatus(QString &message) {
    info_status_.pushText(message, STATUS_CTX_FILTER);
    expertUpdate();
}

void MainStatusBar::popFilterStatus() {
    info_status_.popText(STATUS_CTX_FILTER);
}

void MainStatusBar::pushPacketStatus(QString &message) {
    packet_status_.pushText(message, STATUS_CTX_MAIN);
}

void MainStatusBar::popPacketStatus() {
    packet_status_.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::pushProfileStatus(QString &message) {
    profile_status_.pushText(message, STATUS_CTX_MAIN);
}

void MainStatusBar::popProfileStatus() {
    profile_status_.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::updateCaptureStatistics(capture_options *capture_opts)
{
    QString packets_str;

    if ((capture_opts && capture_opts->cf != cap_file_) || !cap_file_) return;

    /* Do we have any packets? */
    if (cap_file_->count) {
        packets_str.append(QString(tr("Packets: %1 %4 Displayed: %2 %4 Marked: %3"))
                          .arg(cap_file_->count)
                          .arg(cap_file_->displayed_count)
                          .arg(cap_file_->marked_count)
                          .arg(UTF8_MIDDLE_DOT));
        if(cap_file_->drops_known) {
            packets_str.append(QString(tr(" %1 Dropped: %2")).arg(UTF8_MIDDLE_DOT).arg(cap_file_->drops));
        }
        if(cap_file_->ignored_count > 0) {
            packets_str.append(QString(tr(" %1 Ignored: %2")).arg(UTF8_MIDDLE_DOT).arg(cap_file_->ignored_count));
        }
        if(!cap_file_->is_tempfile) {
            /* Loading an existing file */
            gulong computed_elapsed = cf_get_computed_elapsed();
            packets_str.append(QString(tr(" %1  Load time: %2:%3.%4"))
                                        .arg(UTF8_MIDDLE_DOT)
                                        .arg(computed_elapsed/60000)
                                        .arg(computed_elapsed%60000/1000)
                                        .arg(computed_elapsed%1000));
        }
    } else {
        packets_str.append(tr("No Packets"));
    }

    popPacketStatus();
    pushPacketStatus(packets_str);
}

void MainStatusBar::toggleBackground(bool enabled)
{
    if (enabled) {
        setStyleSheet(QString(
                          "QStatusBar {"
                          "  color: #%1;"
                          "  background-color: #%2;"
                          "}"
                          )
                      .arg(tango_aluminium_6, 6, 16, QChar('0'))
                      .arg(tango_butter_2, 6, 16, QChar('0')));
    } else {
        setStyleSheet("");
    }
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
