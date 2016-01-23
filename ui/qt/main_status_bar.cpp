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

#include "file.h"

#include <epan/expert.h>

#include <wsutil/filesystem.h>
#include <wsutil/utf8_entities.h>

#include "ui/main_statusbar.h"
#include "ui/profile.h"
#include "ui/qt/qt_ui_utils.h"


#include "capture_file.h"
#include "main_status_bar.h"
#include "profile_dialog.h"
#include "stock_icon.h"
#include "tango_colors.h"

#include <QAction>
#include <QHBoxLayout>
#include <QSplitter>
#include <QToolButton>

// XXX - The GTK+ code assigns priorities to these and pushes/pops accordingly.

enum StatusContext {
    STATUS_CTX_MAIN,
    STATUS_CTX_FILE,
    STATUS_CTX_FIELD,
    STATUS_CTX_BYTE,
    STATUS_CTX_FILTER,
    STATUS_CTX_PROGRESS,
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

static const int icon_size = 14; // px
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
#endif

    QString button_ss =
            "QToolButton {"
            "  border: none;"
            "  background: transparent;" // Disables platform style on Windows.
            "  padding: 0px;"
            "  margin: 0px;"
            "}";

    expert_button_ = new QToolButton(this);
    expert_button_->setIconSize(QSize(icon_size, icon_size));
    expert_button_->setStyleSheet(button_ss);
    expert_button_->hide();

    // We just want a clickable image. Using a QPushButton or QToolButton would require
    // a lot of adjustment.
    StockIcon comment_icon("x-capture-comment-update");
    comment_button_ = new QToolButton(this);
    comment_button_->setIcon(comment_icon);
    comment_button_->setIconSize(QSize(icon_size, icon_size));
    comment_button_->setStyleSheet(button_ss);

    comment_button_->setToolTip(tr("Open the Capture File Properties dialog"));
    comment_button_->setEnabled(false);
    connect(expert_button_, SIGNAL(clicked(bool)), this, SIGNAL(showExpertInfo()));
    connect(comment_button_, SIGNAL(clicked(bool)), this, SIGNAL(editCaptureComment()));

    info_progress_hb->setContentsMargins(icon_size / 2, 0, 0, 0);

    info_status_.setTemporaryContext(STATUS_CTX_TEMPORARY);
    info_status_.setShrinkable(true);

    info_progress_hb->addWidget(expert_button_);
    info_progress_hb->addWidget(comment_button_);
    info_progress_hb->addWidget(&info_status_);
    info_progress_hb->addWidget(&progress_frame_);
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

    action = ctx_menu_.addAction(tr("Manage Profiles" UTF8_HORIZONTAL_ELLIPSIS));
    action->setData(ProfileDialog::ShowProfiles);
    connect(action, SIGNAL(triggered()), this, SLOT(manageProfile()));
    ctx_menu_.addSeparator();
    action = ctx_menu_.addAction(tr("New" UTF8_HORIZONTAL_ELLIPSIS));
    action->setData(ProfileDialog::NewProfile);
    connect(action, SIGNAL(triggered()), this, SLOT(manageProfile()));
    edit_action_ = ctx_menu_.addAction(tr("Edit" UTF8_HORIZONTAL_ELLIPSIS));
    edit_action_->setData(ProfileDialog::EditCurrentProfile);
    connect(edit_action_, SIGNAL(triggered()), this, SLOT(manageProfile()));
    delete_action_ = ctx_menu_.addAction(tr("Delete"));
    delete_action_->setData(ProfileDialog::DeleteCurrentProfile);
    connect(delete_action_, SIGNAL(triggered()), this, SLOT(manageProfile()));
    ctx_menu_.addSeparator();
    profile_menu_.setTitle(tr("Switch to"));
    ctx_menu_.addMenu(&profile_menu_);

#ifdef QWINTASKBARPROGRESS_H
    progress_frame_.enableTaskbarUpdates(true);
#endif

    connect(wsApp, SIGNAL(appInitialized()), splitter, SLOT(show()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(pushProfileName()));
    connect(&info_status_, SIGNAL(toggleTemporaryFlash(bool)),
            this, SLOT(toggleBackground(bool)));
    connect(wsApp, SIGNAL(profileNameChanged(const gchar *)),
            this, SLOT(pushProfileName()));
    connect(&profile_status_, SIGNAL(mousePressedAt(QPoint,Qt::MouseButton)),
            this, SLOT(showProfileMenu(QPoint,Qt::MouseButton)));

    connect(&progress_frame_, SIGNAL(stopLoading()),
            this, SIGNAL(stopLoading()));
}

void MainStatusBar::showExpert() {
    expertUpdate();
}

void MainStatusBar::captureFileClosing() {
    expert_button_->hide();
    progress_frame_.captureFileClosing();
}

void MainStatusBar::expertUpdate() {
    // <img> won't load @2x versions in Qt versions earlier than 5.4.
    // https://bugreports.qt.io/browse/QTBUG-36383
    // We might have to switch to a QPushButton.
    QString stock_name = "x-expert-";
    QString tt_text = tr(" is the highest expert information level");

    switch(expert_get_highest_severity()) {
    case(PI_ERROR):
        stock_name.append("error");
        tt_text.prepend(tr("ERROR"));
        break;
    case(PI_WARN):
        stock_name.append("warn");
        tt_text.prepend(tr("WARNING"));
        break;
    case(PI_NOTE):
        stock_name.append("note");
        tt_text.prepend(tr("NOTE"));
        break;
    case(PI_CHAT):
        stock_name.append("chat");
        tt_text.prepend(tr("CHAT"));
        break;
//    case(PI_COMMENT):
//        m_expertStatus.setText("<img src=\":/expert/expert_comment.png\"></img>");
//        break;
    default:
        stock_name.append("none");
        tt_text = tr("No expert information");
        break;
    }

    StockIcon expert_icon(stock_name);
    expert_button_->setIcon(expert_icon);
    expert_button_->setToolTip(tt_text);
    expert_button_->show();
}

// ui/gtk/main_statusbar.c
void MainStatusBar::setFileName(CaptureFile &cf)
{
    if (cf.isValid()) {
        popFileStatus();
        QString msgtip = QString("%1 (%2)")
                .arg(cf.capFile()->filename)
                .arg(file_size_to_qstring(cf.capFile()->f_datalen));
        pushFileStatus(cf.fileName(), msgtip);
    }
}

void MainStatusBar::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    comment_button_->setEnabled(cap_file_ != NULL);
}

void MainStatusBar::pushTemporaryStatus(const QString &message) {
    info_status_.pushText(message, STATUS_CTX_TEMPORARY);
}

void MainStatusBar::popTemporaryStatus() {
    info_status_.popText(STATUS_CTX_TEMPORARY);
}

void MainStatusBar::pushFileStatus(const QString &message, const QString &messagetip) {
    info_status_.pushText(message, STATUS_CTX_FILE);
    info_status_.setToolTip(messagetip);
    expertUpdate();
}

void MainStatusBar::popFileStatus() {
    info_status_.popText(STATUS_CTX_FILE);
    info_status_.setToolTip(QString());
}

void MainStatusBar::pushFieldStatus(const QString &message) {
    if (message.isEmpty()) {
        popFieldStatus();
    } else {
        info_status_.pushText(message, STATUS_CTX_FIELD);
    }
}

void MainStatusBar::popFieldStatus() {
    info_status_.popText(STATUS_CTX_FIELD);
}

void MainStatusBar::pushByteStatus(const QString &message)
{
    if (message.isEmpty()) {
        popByteStatus();
    } else {
        info_status_.pushText(message, STATUS_CTX_BYTE);
    }
}

void MainStatusBar::popByteStatus()
{
    info_status_.popText(STATUS_CTX_BYTE);
}

void MainStatusBar::pushFilterStatus(const QString &message) {
    if (message.isEmpty()) {
        popFilterStatus();
    } else {
        info_status_.pushText(message, STATUS_CTX_FILTER);
    }
    expertUpdate();
}

void MainStatusBar::popFilterStatus() {
    info_status_.popText(STATUS_CTX_FILTER);
}

void MainStatusBar::pushPacketStatus(const QString &message) {
    if (message.isEmpty()) {
        popPacketStatus();
    } else {
        packet_status_.pushText(message, STATUS_CTX_MAIN);
    }
}

void MainStatusBar::popPacketStatus() {
    packet_status_.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::pushProfileStatus(const QString &message) {
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

void MainStatusBar::pushBusyStatus(const QString &message, const QString &messagetip)
{
    info_status_.pushText(message, STATUS_CTX_PROGRESS);
    info_status_.setToolTip(messagetip);
    progress_frame_.showBusy(true, false, NULL);
}

void MainStatusBar::popBusyStatus()
{
    info_status_.popText(STATUS_CTX_PROGRESS);
    info_status_.setToolTip(QString());
    progress_frame_.hide();
}

void MainStatusBar::popProfileStatus() {
    profile_status_.popText(STATUS_CTX_MAIN);
}

void MainStatusBar::pushProgressStatus(const QString &message, bool animate, bool terminate_is_stop, gboolean *stop_flag)
{
    info_status_.pushText(message, STATUS_CTX_PROGRESS);
    progress_frame_.showProgress(animate, terminate_is_stop, stop_flag);
}

void MainStatusBar::updateProgressStatus(int value)
{
    progress_frame_.setValue(value);
}

void MainStatusBar::popProgressStatus()
{
    info_status_.popText(STATUS_CTX_PROGRESS);
    progress_frame_.hide();
}

void MainStatusBar::updateCaptureStatistics(capture_session *cap_session)
{
    QString packets_str;

#ifndef HAVE_LIBPCAP
    Q_UNUSED(cap_session)
#else
    /* Do we have any packets? */
    if ((!cap_session || cap_session->cf == cap_file_) && cap_file_ && cap_file_->count) {
        packets_str.append(QString(tr("Packets: %1 %4 Displayed: %2 (%3%)"))
                          .arg(cap_file_->count)
                          .arg(cap_file_->displayed_count)
                          .arg((100.0*cap_file_->displayed_count)/cap_file_->count, 0, 'f', 1)
                          .arg(UTF8_MIDDLE_DOT));
        if(cap_file_->marked_count > 0) {
            packets_str.append(QString(tr(" %1 Marked: %2 (%3%)"))
                              .arg(UTF8_MIDDLE_DOT)
                              .arg(cap_file_->marked_count)
                              .arg((100.0*cap_file_->marked_count)/cap_file_->count, 0, 'f', 1));
        }
        if(cap_file_->drops_known) {
            packets_str.append(QString(tr(" %1 Dropped: %2 (%3%)"))
                              .arg(UTF8_MIDDLE_DOT)
                              .arg(cap_file_->drops)
                              .arg((100.0*cap_file_->drops)/cap_file_->count, 0, 'f', 1));
        }
        if(cap_file_->ignored_count > 0) {
            packets_str.append(QString(tr(" %1 Ignored: %2 (%3%)"))
                              .arg(UTF8_MIDDLE_DOT)
                              .arg(cap_file_->ignored_count)
                              .arg((100.0*cap_file_->ignored_count)/cap_file_->count, 0, 'f', 1));
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

void MainStatusBar::updateCaptureFixedStatistics(capture_session *cap_session)
{
    QString packets_str;

#ifndef HAVE_LIBPCAP
    Q_UNUSED(cap_session)
#else
    /* Do we have any packets? */
    if (cap_session->count) {
        packets_str.append(QString(tr("Packets: %1"))
                          .arg(cap_session->count));
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
    const gchar *profile_name = get_profile_name();
    bool separator_added = false;
    GList *fl_entry;
    profile_def *profile;
    QAction *pa;

    init_profile_list();
    fl_entry = current_profile_list();

    profile_menu_.clear();
    while (fl_entry && fl_entry->data) {
        profile = (profile_def *) fl_entry->data;
        if (!profile->is_global || !profile_exists(profile->name, false)) {
            if (profile->is_global && !separator_added) {
                profile_menu_.addSeparator();
                separator_added = true;
            }
            pa = profile_menu_.addAction(profile->name);
            if (strcmp(profile->name, profile_name) == 0) {
                /* Current profile */
                pa->setCheckable(true);
                pa->setChecked(true);
            }
            connect(pa, SIGNAL(triggered()), this, SLOT(switchToProfile()));
        }
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
        setStyleSheet(QString());
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
