/* main_status_bar.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "file.h"

#include <epan/expert.h>
#include <epan/prefs.h>

#include <wsutil/filesystem.h>
#include <wsutil/utf8_entities.h>

#include "ui/main_statusbar.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/main_window.h>

#include "capture_file.h"
#include "main_status_bar.h"
#include "profile_dialog.h"
#include <ui/qt/utils/stock_icon.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/capture_file.h>
#include <ui/qt/widgets/clickable_label.h>

#include <QAction>
#include <QActionGroup>
#include <QHBoxLayout>
#include <QSplitter>
#include <QToolButton>
#include <QLatin1Char>

// To do:
// - Use the CaptureFile class.

// XXX - The GTK+ code assigns priorities to these and pushes/pops accordingly.

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
    push_msg = QString::vasprintf(msg_format, ap);
    va_end(ap);

    mainApp->pushStatus(WiresharkApplication::TemporaryStatus, push_msg);
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
    #ifdef HAVE_LIBPCAP
    ready_msg_(tr("Ready to load or capture")),
    #else
    ready_msg_(tr("Ready to load file")),
    #endif
    cs_fixed_(false),
    cs_count_(0)
{
    QSplitter *splitter = new QSplitter(this);
    QWidget *info_progress = new QWidget(this);
    QHBoxLayout *info_progress_hb = new QHBoxLayout(info_progress);

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

#ifdef Q_OS_MAC
    profile_status_.setAttribute(Qt::WA_MacSmallSize, true);
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
    info_status_.pushText(ready_msg_, STATUS_CTX_MAIN);
    packets_bar_update();

#ifdef QWINTASKBARPROGRESS_H
    progress_frame_.enableTaskbarUpdates(true);
#endif

    connect(mainApp, SIGNAL(appInitialized()), splitter, SLOT(show()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(appInitialized()));
    connect(&info_status_, SIGNAL(toggleTemporaryFlash(bool)),
            this, SLOT(toggleBackground(bool)));
    connect(mainApp, SIGNAL(profileNameChanged(const gchar *)),
            this, SLOT(setProfileName()));
    connect(&profile_status_, SIGNAL(clickedAt(QPoint,Qt::MouseButton)),
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
    popGenericStatus(STATUS_CTX_FIELD);
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
        popGenericStatus(STATUS_CTX_FILE);
        QString msgtip = QString("%1 (%2)")
                .arg(cf.capFile()->filename)
                .arg(file_size_to_qstring(cf.capFile()->f_datalen));
        pushGenericStatus(STATUS_CTX_FILE, cf.fileName(), msgtip);
    }
}

void MainStatusBar::changeEvent(QEvent *event)
{
    if (event->type() == QEvent::LanguageChange) {
        info_status_.popText(STATUS_CTX_MAIN);
        info_status_.pushText(ready_msg_, STATUS_CTX_MAIN);
        setStatusbarForCaptureFile();
        showCaptureStatistics();
        setProfileName();
    }
    QStatusBar::changeEvent(event);
}

void MainStatusBar::setCaptureFile(capture_file *cf)
{
    cap_file_ = cf;
    comment_button_->setEnabled(cap_file_ != NULL);
}

void MainStatusBar::setStatusbarForCaptureFile()
{
    if (cap_file_ && cap_file_->filename && (cap_file_->state != FILE_CLOSED)) {
        popGenericStatus(STATUS_CTX_FILE);
        QString msgtip = QString("%1 (%2)")
                .arg(cap_file_->filename)
                .arg(file_size_to_qstring(cap_file_->f_datalen));
        pushGenericStatus(STATUS_CTX_FILE, cf_get_display_name(cap_file_), msgtip);
    }
}

void MainStatusBar::selectedFieldChanged(FieldInformation * finfo)
{
    QString item_info;

    if (! finfo) {
        pushGenericStatus(STATUS_CTX_FIELD, item_info);
        return;
    }

    FieldInformation::HeaderInfo hInfo = finfo->headerInfo();

    if (hInfo.isValid)
    {
        if (hInfo.description.length() > 0) {
            item_info.append(hInfo.description);
        } else {
            item_info.append(hInfo.name);
        }
    }

    if (!item_info.isEmpty()) {
        int finfo_length;
        if (hInfo.isValid)
            item_info.append(" (" + hInfo.abbreviation + ")");

        finfo_length = finfo->position().length + finfo->appendix().length;
        if (finfo_length > 0) {
            item_info.append(", " + tr("%Ln byte(s)", "", finfo_length));
        }
    }

    pushGenericStatus(STATUS_CTX_FIELD, item_info);
}

void MainStatusBar::highlightedFieldChanged(FieldInformation * finfo)
{
    QString hint;

    if (finfo)
    {
        FieldInformation::Position pos = finfo->position();
        QString field_str;

        if (pos.length < 2) {
            hint = QString(tr("Byte %1")).arg(pos.start);
        } else {
            hint = QString(tr("Bytes %1-%2")).arg(pos.start).arg(pos.start + pos.length - 1);
        }
        hint += QString(": %1 (%2)")
                .arg(finfo->headerInfo().name)
                .arg(finfo->headerInfo().abbreviation);
    }

    pushGenericStatus(STATUS_CTX_BYTE, hint);
}

void MainStatusBar::pushGenericStatus(StatusContext status, const QString &message, const QString &messagetip)
{
    LabelStack * stack = &info_status_;

    if (status == STATUS_CTX_MAIN)
        stack = &packet_status_;

    if (message.isEmpty() && status != STATUS_CTX_FILE  && status != STATUS_CTX_TEMPORARY && status != STATUS_CTX_PROGRESS)
        popGenericStatus(status);
    else
        stack->pushText(message, status);

    stack->setToolTip(messagetip);

    if (status == STATUS_CTX_FILTER || status == STATUS_CTX_FILE)
        expertUpdate();
}

void MainStatusBar::popGenericStatus(StatusContext status)
{
    LabelStack * stack = &info_status_;

    if (status == STATUS_CTX_MAIN)
        stack = &packet_status_;

    stack->setToolTip(QString());

    stack->popText(status);
}

void MainStatusBar::setProfileName()
{
    profile_status_.setText(tr("Profile: %1").arg(get_profile_name()));
}

void MainStatusBar::appInitialized()
{
    setProfileName();
    connect(mainApp->mainWindow(), SIGNAL(framesSelected(QList<int>)), this, SLOT(selectedFrameChanged(QList<int>)));
}

void MainStatusBar::selectedFrameChanged(QList<int>)
{
    showCaptureStatistics();
}

void MainStatusBar::showCaptureStatistics()
{
    QString packets_str;

    QList<int> rows;
    MainWindow * mw = qobject_cast<MainWindow *>(mainApp->mainWindow());
    if (mw)
        rows = mw->selectedRows(true);

#ifdef HAVE_LIBPCAP
    if (cap_file_) {
        /* Do we have any packets? */
        if (cs_fixed_ && cs_count_ > 0) {
            if (prefs.gui_qt_show_selected_packet && rows.count() == 1) {
                packets_str.append(QString(tr("Selected Packet: %1 %2 "))
                                   .arg(rows.at(0))
                                   .arg(UTF8_MIDDLE_DOT));
            }
            packets_str.append(QString(tr("Packets: %1"))
                               .arg(cs_count_));
        } else if (cs_count_ > 0) {
            if (prefs.gui_qt_show_selected_packet && rows.count() == 1) {
                packets_str.append(QString(tr("Selected Packet: %1 %2 "))
                                   .arg(rows.at(0))
                                   .arg(UTF8_MIDDLE_DOT));
            }
            packets_str.append(QString(tr("Packets: %1 %4 Displayed: %2 (%3%)"))
                               .arg(cap_file_->count)
                               .arg(cap_file_->displayed_count)
                               .arg((100.0*cap_file_->displayed_count)/cap_file_->count, 0, 'f', 1)
                               .arg(UTF8_MIDDLE_DOT));
            if (rows.count() > 1) {
                packets_str.append(QString(tr(" %1 Selected: %2 (%3%)"))
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(rows.count())
                                   .arg((100.0*rows.count())/cap_file_->count, 0, 'f', 1));
            }
            if (cap_file_->marked_count > 0) {
                packets_str.append(QString(tr(" %1 Marked: %2 (%3%)"))
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->marked_count)
                                   .arg((100.0*cap_file_->marked_count)/cap_file_->count, 0, 'f', 1));
            }
            if (cap_file_->drops_known) {
                packets_str.append(QString(tr(" %1 Dropped: %2 (%3%)"))
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->drops)
                                   .arg((100.0*cap_file_->drops)/cap_file_->count, 0, 'f', 1));
            }
            if (cap_file_->ignored_count > 0) {
                packets_str.append(QString(tr(" %1 Ignored: %2 (%3%)"))
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(cap_file_->ignored_count)
                                   .arg((100.0*cap_file_->ignored_count)/cap_file_->count, 0, 'f', 1));
            }
            if (cap_file_->packet_comment_count > 0) {
                packets_str.append(QString(tr(" %1 Comments: %2"))
                    .arg(UTF8_MIDDLE_DOT)
                    .arg(cap_file_->packet_comment_count));
            }
            if (prefs.gui_qt_show_file_load_time && !cap_file_->is_tempfile) {
                /* Loading an existing file */
                gulong computed_elapsed = cf_get_computed_elapsed(cap_file_);
                packets_str.append(QString(tr(" %1  Load time: %2:%3.%4"))
                                   .arg(UTF8_MIDDLE_DOT)
                                   .arg(computed_elapsed/60000, 2, 10, QLatin1Char('0'))
                                   .arg(computed_elapsed%60000/1000, 2, 10, QLatin1Char('0'))
                                   .arg(computed_elapsed%1000, 3, 10, QLatin1Char('0')));
            }
        }
    }
#endif // HAVE_LIBPCAP

    if (packets_str.isEmpty()) {
        packets_str = tr("No Packets");
    }

    popGenericStatus(STATUS_CTX_MAIN);
    pushGenericStatus(STATUS_CTX_MAIN, packets_str);
}

void MainStatusBar::updateCaptureStatistics(capture_session *cap_session)
{
    cs_fixed_ = false;

#ifndef HAVE_LIBPCAP
    Q_UNUSED(cap_session)
#else
    if ((!cap_session || cap_session->cf == cap_file_) && cap_file_ && cap_file_->count) {
        cs_count_ = cap_file_->count;
    } else {
        cs_count_ = 0;
    }
#endif // HAVE_LIBPCAP

    showCaptureStatistics();
}

void MainStatusBar::updateCaptureFixedStatistics(capture_session *cap_session)
{
    cs_fixed_ = true;

#ifndef HAVE_LIBPCAP
    Q_UNUSED(cap_session)
#else
    if (cap_session && cap_session->count) {
        cs_count_ = cap_session->count;
    } else {
        cs_count_ = 0;
    }
#endif // HAVE_LIBPCAP

    showCaptureStatistics();
}

void MainStatusBar::showProfileMenu(const QPoint &global_pos, Qt::MouseButton button)
{
    ProfileModel model;

    QMenu * profile_menu_ = new QMenu(this);
    profile_menu_->setAttribute(Qt::WA_DeleteOnClose);
    QActionGroup * global = new QActionGroup(profile_menu_);
    QActionGroup * user = new QActionGroup(profile_menu_);

    for (int cnt = 0; cnt < model.rowCount(); cnt++)
    {
        QModelIndex idx = model.index(cnt, ProfileModel::COL_NAME);
        if (! idx.isValid())
            continue;


        QAction * pa = Q_NULLPTR;
        QString name = idx.data().toString();

        // An ampersand in the menu item's text sets Alt+F as a shortcut for this menu.
        // Use "&&" to get a real ampersand in the menu bar.
        name.replace('&', "&&");

        if (idx.data(ProfileModel::DATA_IS_DEFAULT).toBool())
        {
            pa = profile_menu_->addAction(name);
        }
        else if (idx.data(ProfileModel::DATA_IS_GLOBAL).toBool())
        {
            /* Check if this profile does not exist as user */
            if (cnt == model.findByName(name))
                pa = global->addAction(name);
        }
        else
            pa = user->addAction(name);

        if (! pa)
            continue;

        pa->setCheckable(true);
        if (idx.data(ProfileModel::DATA_IS_SELECTED).toBool())
            pa->setChecked(true);

        pa->setFont(idx.data(Qt::FontRole).value<QFont>());
        pa->setProperty("profile_name", idx.data());
        pa->setProperty("profile_is_global", idx.data(ProfileModel::DATA_IS_GLOBAL));

        connect(pa, &QAction::triggered, this, &MainStatusBar::switchToProfile);
    }

    profile_menu_->addActions(user->actions());
    profile_menu_->addSeparator();
    profile_menu_->addActions(global->actions());

    if (button == Qt::LeftButton) {
        profile_menu_->popup(global_pos);
    } else {

        bool enable_edit = false;

        QModelIndex idx = model.activeProfile();
        if (! idx.data(ProfileModel::DATA_IS_DEFAULT).toBool() && ! idx.data(ProfileModel::DATA_IS_GLOBAL).toBool())
            enable_edit = true;

        profile_menu_->setTitle(tr("Switch to"));
        QMenu * ctx_menu_ = new QMenu(this);
        ctx_menu_->setAttribute(Qt::WA_DeleteOnClose);
        QAction * action = ctx_menu_->addAction(tr("Manage Profiles…"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::ShowProfiles);

        ctx_menu_->addSeparator();
        action = ctx_menu_->addAction(tr("New…"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::NewProfile);
        action = ctx_menu_->addAction(tr("Edit…"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::EditCurrentProfile);
        action->setEnabled(enable_edit);
        action = ctx_menu_->addAction(tr("Delete"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::DeleteCurrentProfile);
        action->setEnabled(enable_edit);
        ctx_menu_->addSeparator();

#ifdef HAVE_MINIZIP
        QMenu * importMenu = new QMenu(tr("Import"));
        action = importMenu->addAction(tr("from zip file"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::ImportZipProfile);
        action = importMenu->addAction(tr("from directory"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::ImportDirProfile);
        ctx_menu_->addMenu(importMenu);

        if (model.userProfilesExist())
        {
            QMenu * exportMenu = new QMenu(tr("Export"), ctx_menu_);
            if (enable_edit)
            {
                action = exportMenu->addAction(tr("selected personal profile"), this, SLOT(manageProfile()));
                action->setProperty("dialog_action_", (int)ProfileDialog::ExportSingleProfile);
                action->setEnabled(enable_edit);
            }
            action = exportMenu->addAction(tr("all personal profiles"), this, SLOT(manageProfile()));
            action->setProperty("dialog_action_", (int)ProfileDialog::ExportAllProfiles);
            ctx_menu_->addMenu(exportMenu);
        }

#else
        action = ctx_menu_->addAction(tr("Import"), this, SLOT(manageProfile()));
        action->setProperty("dialog_action_", (int)ProfileDialog::ImportDirProfile);
#endif
        ctx_menu_->addSeparator();

        ctx_menu_->addMenu(profile_menu_);
        ctx_menu_->popup(global_pos);
    }
}

void MainStatusBar::toggleBackground(bool enabled)
{
    if (enabled) {
        setStyleSheet(QString(
                          "QStatusBar {"
                          "  background-color: %2;"
                          "}"
                          )
                      .arg(ColorUtils::warningBackground().name()));
    } else {
        setStyleSheet(QString());
    }
}

void MainStatusBar::switchToProfile()
{
    QAction *pa = qobject_cast<QAction*>(sender());

    if (pa && pa->property("profile_name").isValid()) {
        QString profile = pa->property("profile_name").toString();
        mainApp->setConfigurationProfile(profile.toUtf8().constData());
    }
}

void MainStatusBar::manageProfile()
{
    QAction *pa = qobject_cast<QAction*>(sender());

    if (pa) {
        ProfileDialog cp_dialog;

        int profileAction = pa->property("dialog_action_").toInt();
        cp_dialog.execAction(static_cast<ProfileDialog::ProfileAction>(profileAction));
    }
}

void MainStatusBar::captureEventHandler(CaptureEvent ev)
{
    switch(ev.captureContext())
    {
#ifdef HAVE_LIBPCAP
    case CaptureEvent::Update:
        switch (ev.eventType())
        {
        case CaptureEvent::Continued:
            updateCaptureStatistics(ev.capSession());
            break;
        default:
            break;
        }
        break;
    case CaptureEvent::Fixed:
        switch (ev.eventType())
        {
        case CaptureEvent::Continued:
            updateCaptureFixedStatistics(ev.capSession());
            break;
        default:
            break;
        }
        break;
#endif
    case CaptureEvent::Save:
        switch (ev.eventType())
        {
        case CaptureEvent::Finished:
        case CaptureEvent::Failed:
        case CaptureEvent::Stopped:
            popGenericStatus(STATUS_CTX_FILE);
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }
}
