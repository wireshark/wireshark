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

#include "wireshark_application.h"

#include "globals.h"

#include "epan/expert.h"

#include "ui/main_statusbar.h"
#include "ui/utf8_entities.h"

#include <QSplitter>
#include <QHBoxLayout>

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE QObject::tr(" Ready to load or capture")
#else
#define DEF_READY_MESSAGE QObject::tr(" Ready to load file")
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
static MainStatusBar *cur_main_status_bar = NULL;

/*
 * Push a formatted temporary message onto the statusbar.
 */
void
statusbar_push_temporary_msg(const gchar *msg_format, ...)
{
    va_list ap;
    gchar *msg;
    QString pushMsg;

    if (!cur_main_status_bar) return;

    va_start(ap, msg_format);
    msg = g_strdup_vprintf(msg_format, ap);
    va_end(ap);

    pushMsg.fromUtf8(msg);
    g_free(msg);

    cur_main_status_bar->pushTemporaryStatus(pushMsg);
}

/*
 * Update the packets statusbar to the current values
 */
void
packets_bar_update(void)
{
    QString packetsStr = QString("");

    if (!cur_main_status_bar) return;

    cur_main_status_bar->popPacketStatus();

    /* Do we have any packets? */
    if (cfile.count) {
        packetsStr.append(QString("Packets: %1 " UTF8_MIDDLE_DOT " Displayed: %2 " UTF8_MIDDLE_DOT " Marked: %3")
//        packetsStr.append(QString(QObject::tr("Packets: %1 Displayed: %2 Marked: %3"))
                          .arg(cfile.count)
                          .arg(cfile.displayed_count)
                          .arg(cfile.marked_count));
        if(cfile.drops_known) {
            packetsStr.append(QString(" " UTF8_MIDDLE_DOT " Dropped: %1")).arg(cfile.drops);
        }
        if(cfile.ignored_count > 0) {
            packetsStr.append(QString(" " UTF8_MIDDLE_DOT " Ignored: %1").arg(cfile.ignored_count));
        }
        if(!cfile.is_tempfile) {
            /* Loading an existing file */
            gulong computed_elapsed = cf_get_computed_elapsed();
            packetsStr.append(QString(" " UTF8_MIDDLE_DOT " Load time: %1:%2.%3")
                                        .arg(computed_elapsed/60000)
                                        .arg(computed_elapsed%60000/1000)
                                        .arg(computed_elapsed%1000));
            /*packetsStr.append(QString().sprintf(QObject::tr(" Load time: %lu:%02lu.%03lu",
                                        computed_elapsed/60000,
                                        computed_elapsed%60000/1000,
                                        computed_elapsed%1000)));
            */
        }
    } else {
        packetsStr.append(QObject::tr("No Packets"));
    }

    cur_main_status_bar->pushPacketStatus(packetsStr);
}

MainStatusBar::MainStatusBar(QWidget *parent) :
    QStatusBar(parent)
{
    QSplitter *splitter = new QSplitter(this);
    QString readyMsg(DEF_READY_MESSAGE);
    QWidget *infoProgress = new QWidget(this);
    QHBoxLayout *infoProgressHB = new QHBoxLayout(infoProgress);

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
    m_expertStatus.setAttribute(Qt::WA_MacSmallSize, true);
#endif

//    infoProgress->setStyleSheet("QWidget { border: 0.5px dotted red; }"); // Debug layout
    m_expertStatus.setTextFormat(Qt::RichText);
    m_expertStatus.hide();

    // XXX Add the comment icon

    infoProgressHB->setContentsMargins(0, 0, 0, 0);

    m_infoStatus.setTemporaryContext(STATUS_CTX_TEMPORARY);

    infoProgressHB->addWidget(&m_expertStatus);
    infoProgressHB->addWidget(&m_infoStatus);
    infoProgressHB->addWidget(&m_progressBar);
    infoProgressHB->addStretch(10);

    splitter->addWidget(infoProgress);
    splitter->addWidget(&m_packetStatus);
    splitter->addWidget(&m_profileStatus);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 3);
    splitter->setStretchFactor(2, 1);

    addWidget(splitter, 1);

    cur_main_status_bar = this;

    m_infoStatus.pushText(readyMsg, STATUS_CTX_MAIN);
    packets_bar_update();
}

void MainStatusBar::showExpert() {
    expertUpdate();
}

void MainStatusBar::hideExpert() {
    m_expertStatus.hide();
}

void MainStatusBar::expertUpdate() {
    QString imgText = "<img src=\":/expert/expert_";
    QString ttText = " is the highest expert info level";

    switch(expert_get_highest_severity()) {
    case(PI_ERROR):
        imgText.append("error");
        ttText.prepend("ERROR");
        break;
    case(PI_WARN):
        imgText.append("warn");
        ttText.prepend("WARNING");
        break;
    case(PI_NOTE):
        imgText.append("note");
        ttText.prepend("NOTE");
        break;
    case(PI_CHAT):
        imgText.append("chat");
        ttText.prepend("CHAT");
        break;
//    case(PI_COMMENT):
//        m_expertStatus.setText("<img src=\":/expert/expert_comment.png\"></img>");
//        break;
    default:
        imgText.append("none");
        ttText = "No expert info";
        break;
    }

    imgText.append(".png\"></img>");
    m_expertStatus.setText(imgText);
    m_expertStatus.setToolTip(ttText);
    m_expertStatus.show();
}

void MainStatusBar::pushTemporaryStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_TEMPORARY);
}

void MainStatusBar::popTemporaryStatus() {
    m_infoStatus.popText(STATUS_CTX_TEMPORARY);
}

void MainStatusBar::pushFileStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_FILE);
    expertUpdate();
}

void MainStatusBar::popFileStatus() {
    m_infoStatus.popText(STATUS_CTX_FILE);
}

void MainStatusBar::pushFieldStatus(QString &message) {
    if (message.isNull()) {
        popFieldStatus();
    } else {
        m_infoStatus.pushText(message, STATUS_CTX_FIELD);
    }
}

void MainStatusBar::popFieldStatus() {
    m_infoStatus.popText(STATUS_CTX_FIELD);
}

void MainStatusBar::pushFilterStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_FILTER);
    expertUpdate();
}

void MainStatusBar::popFilterStatus() {
    m_infoStatus.popText(STATUS_CTX_FILTER);
}

void MainStatusBar::pushPacketStatus(QString &message) {
    m_packetStatus.pushText(message, STATUS_CTX_MAIN);
}

void MainStatusBar::popPacketStatus() {
    m_packetStatus.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::pushProfileStatus(QString &message) {
    m_profileStatus.pushText(message, STATUS_CTX_MAIN);
}

void MainStatusBar::popProfileStatus() {
    m_profileStatus.popText(STATUS_CTX_MAIN);
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
