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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include "main_status_bar.h"

#include "wireshark_application.h"

#include "globals.h"

#include "ui/main_statusbar.h"

#include <QSplitter>

#ifdef HAVE_LIBPCAP
#define DEF_READY_MESSAGE " Ready to load or capture"
#else
#define DEF_READY_MESSAGE " Ready to load file"
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
        packetsStr.append(QString("Packets: %1 Displayed: %2 Marked: %3")
                          .arg(cfile.count)
                          .arg(cfile.displayed_count)
                          .arg(cfile.marked_count));
        if(cfile.drops_known) {
            packetsStr.append(QString(" Dropped: %1").arg(cfile.drops));
        }
        if(cfile.ignored_count > 0) {
            packetsStr.append(QString(" Ignored: %1").arg(cfile.ignored_count));
        }
        if(!cfile.is_tempfile) {
            /* Loading an existing file */
            gulong computed_elapsed = cf_get_computed_elapsed();
            packetsStr.append(QString().sprintf(" Load time: %lu:%02lu.%03lu",
                                        computed_elapsed/60000,
                                        computed_elapsed%60000/1000,
                                        computed_elapsed%1000));
        }
    } else {
        packetsStr.append("No Packets");
    }

    cur_main_status_bar->pushPacketStatus(packetsStr);
}

MainStatusBar::MainStatusBar(QWidget *parent) :
    QStatusBar(parent)
{
    QSplitter *splitter = new QSplitter(this);
    QString readyMsg(DEF_READY_MESSAGE);

    // XXX - Add the expert level icon

    m_infoStatus.setTemporaryContext(STATUS_CTX_TEMPORARY);
    splitter->addWidget(&m_infoStatus);
    splitter->addWidget(&m_packetStatus);
    splitter->addWidget(&m_profileStatus);

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 3);
    splitter->setStretchFactor(2, 0);

    addWidget(splitter, 1);

    cur_main_status_bar = this;

    m_infoStatus.pushText(readyMsg, STATUS_CTX_MAIN);
    packets_bar_update();
}

void MainStatusBar::pushTemporaryStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_TEMPORARY);
}

void MainStatusBar::popTemporaryStatus() {
    m_infoStatus.popText(STATUS_CTX_TEMPORARY);
}

void MainStatusBar::pushFileStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_FILE);
}

void MainStatusBar::popFileStatus() {
    m_infoStatus.popText(STATUS_CTX_FILE);
}

void MainStatusBar::pushFieldStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_FIELD);
}

void MainStatusBar::popFieldStatus() {
    m_infoStatus.popText(STATUS_CTX_FIELD);
}

void MainStatusBar::pushFilterStatus(QString &message) {
    m_infoStatus.pushText(message, STATUS_CTX_FILTER);
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

