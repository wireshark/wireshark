/* main_status_bar.cpp
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

#include "epan/expert.h"
#include "wsutil/filesystem.h"

#include "ui/main_statusbar.h"
#include "ui/profile.h"
#include "ui/utf8_entities.h"

#include "main_status_bar.h"
#include "profile_dialog.h"

#include <QSplitter>
#include <QHBoxLayout>
#include <QAction>

#include "tango_colors.h"


// XXX - The GTK+ code assigns priorities to these and pushes/pops accordingly.

enum StatusContext {
    STATUS_CTX_MAIN,
    STATUS_CTX_FILE,
    STATUS_CTX_FIELD,
    STATUS_CTX_FILTER,
    STATUS_CTX_TEMPORARY
};

Q_DECLARE_METATYPE(ProfileDialog::ProfileAction)

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
    QString push_msg;

    if (!cur_main_status_bar_) return;

    va_start(ap, msg_format);
    push_msg.vsprintf(msg_format, ap);
    va_end(ap);

    cur_main_status_bar_->pushTemporaryStatus(push_msg);
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
    cap_file_(NULL),
    edit_action_(NULL),
    delete_action_(NULL)
{
    QSplitter *splitter = new QSplitter(this);
    #ifdef HAVE_LIBPCAP
    QString ready_msg(tr("Ready to load or capture"));
    #else
    QString ready_msg(tr("Ready to load file"));
    #endif
    QWidget *info_progress = new QWidget(this);
    QHBoxLayout *info_progress_hb = new QHBoxLayout(info_progress);
    QAction *action;

#if defined(Q_OS_WIN)
    // Handles are the same color as widgets, at least on Windows 7.
    splitter->setHandleWidth(3);
    splitter->setStyleSheet(QString(
                                "QSplitter::handle {"
                                "  border-left: 1px solid palette(mid);"
                                "  border-right: 1px solid palette(mid);"
                                "}"
                                ));
#elif defined(Q_OS_MAC)
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

    action = ctx_menu_.addAction(tr("Manage Profiles..."));
    action->setData(ProfileDialog::ShowProfiles);
    connect(action, SIGNAL(triggered()), this, SLOT(manageProfile()));
    ctx_menu_.addSeparator();
    action = ctx_menu_.addAction(tr("New..."));
    action->setData(ProfileDialog::NewProfile);
    connect(action, SIGNAL(triggered()), this, SLOT(manageProfile()));
    edit_action_ = ctx_menu_.addAction(tr("Edit..."));
    edit_action_->setData(ProfileDialog::EditCurrentProfile);
    connect(edit_action_, SIGNAL(triggered()), this, SLOT(manageProfile()));
    delete_action_ = ctx_menu_.addAction(tr("Delete"));
    delete_action_->setData(ProfileDialog::DeleteCurrentProfile);
    connect(delete_action_, SIGNAL(triggered()), this, SLOT(manageProfile()));
    ctx_menu_.addSeparator();
    profile_menu_.setTitle(tr("Switch to"));
    ctx_menu_.addMenu(&profile_menu_);

    connect(wsApp, SIGNAL(appInitialized()), splitter, SLOT(show()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(pushProfileName()));
    connect(&info_status_, SIGNAL(toggleTemporaryFlash(bool)),
            this, SLOT(toggleBackground(bool)));
    connect(wsApp, SIGNAL(captureCaptureUpdateContinue(capture_session*)),
            this, SLOT(updateCaptureStatistics(capture_session*)));
    connect(wsApp, SIGNAL(configurationProfileChanged(const gchar *)),
            this, SLOT(pushProfileName()));
    connect(&profile_status_, SIGNAL(mousePressedAt(QPoint,Qt::MouseButton)),
            this, SLOT(showProfileMenu(QPoint,Qt::MouseButton)));
}

void MainStatusBar::showExpert() {
    expertUpdate();
}

void MainStatusBar::hideExpert() {
    expert_status_.hide();
}

void MainStatusBar::expertUpdate() {
    QString img_text = "<img src=\":/expert/expert_";
    QString tt_text = tr(" is the highest expert info level");

    switch(expert_get_highest_severity()) {
    case(PI_ERROR):
        img_text.append("error");
        tt_text.prepend(tr("ERROR"));
        break;
    case(PI_WARN):
        img_text.append("warn");
        tt_text.prepend(tr("WARNING"));
        break;
    case(PI_NOTE):
        img_text.append("note");
        tt_text.prepend(tr("NOTE"));
        break;
    case(PI_CHAT):
        img_text.append("chat");
        tt_text.prepend(tr("CHAT"));
        break;
//    case(PI_COMMENT):
//        m_expertStatus.setText("<img src=\":/expert/expert_comment.png\"></img>");
//        break;
    default:
        img_text.append("none");
        tt_text = tr("No expert info");
        break;
    }

    img_text.append(".png\"></img>");
    expert_status_.setText(img_text);
    expert_status_.setToolTip(tt_text);
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

void MainStatusBar::pushProfileName()
{
    const gchar *cur_profile = get_profile_name();
    QString status = tr("Profile: ") + cur_profile;

    popProfileStatus();
    pushProfileStatus(status);

    if (profile_exists(cur_profile, FALSE) && strcmp (cur_profile, DEFAULT_PROFILE) != 0) {
        edit_action_->setEnabled(true);
        delete_action_->setEnabled(true);
    } else {
        edit_action_->setEnabled(false);
        delete_action_->setEnabled(false);
    }
}

void MainStatusBar::popProfileStatus() {
    profile_status_.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::updateCaptureStatistics(capture_session *cap_session _U_)
{
    QString packets_str;

#ifdef HAVE_LIBPCAP
    /* Do we have any packets? */
    if ((!cap_session || cap_session->cf == cap_file_) && cap_file_ && cap_file_->count) {
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
            gulong computed_elapsed = cf_get_computed_elapsed(cap_file_);
            packets_str.append(QString(tr(" %1  Load time: %2:%3.%4"))
                                        .arg(UTF8_MIDDLE_DOT)
                                        .arg(computed_elapsed/60000)
                                        .arg(computed_elapsed%60000/1000)
                                        .arg(computed_elapsed%1000));
        }
    } else {
#endif // HAVE_LIBPCAP
        packets_str = tr("No Packets");
#ifdef HAVE_LIBPCAP
    }
#endif // HAVE_LIBPCAP

    popPacketStatus();
    pushPacketStatus(packets_str);
}

void MainStatusBar::showProfileMenu(const QPoint &global_pos, Qt::MouseButton button)
{
    GList *fl_entry;
    profile_def *profile;
    QAction *pa;

    init_profile_list();
    fl_entry = edited_profile_list();

    profile_menu_.clear();
    while (fl_entry && fl_entry->data) {
        profile = (profile_def *) fl_entry->data;
        pa = profile_menu_.addAction(profile->name);
        connect(pa, SIGNAL(triggered()), this, SLOT(switchToProfile()));
        fl_entry = g_list_next(fl_entry);
    }

    if (button == Qt::LeftButton) {
        profile_menu_.exec(global_pos);
    } else {
        ctx_menu_.exec(global_pos);
    }
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
                      .arg(ws_css_warn_text, 6, 16, QChar('0'))
                      .arg(ws_css_warn_background, 6, 16, QChar('0')));
    } else {
        setStyleSheet("");
    }
}

void MainStatusBar::switchToProfile()
{
    QAction *pa = qobject_cast<QAction*>(sender());

    if (pa) {
        wsApp->setConfigurationProfile(pa->text().toUtf8().constData());
    }
}

void MainStatusBar::manageProfile()
{
    QAction *pa = qobject_cast<QAction*>(sender());

    if (pa) {
        ProfileDialog cp_dialog;
        cp_dialog.execAction(static_cast<ProfileDialog::ProfileAction>(pa->data().toInt()));
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
