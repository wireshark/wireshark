/* main_welcome.cpp
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

#include <epan/prefs.h>

#include "ui/capture_globals.h"
#include "ui/help_url.h"

#include "ws_version_info.h"

#include "main_welcome.h"
#include <ui_main_welcome.h>
#include "tango_colors.h"

#include "color_utils.h"
#include "qt_ui_utils.h"
#include "wireshark_application.h"

#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QListWidget>
#include <QMenu>
#include <QResizeEvent>
#include <QTreeWidgetItem>
#include <QUrl>
#include <QWidget>

#if QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
#include <QGraphicsBlurEffect>
#endif

#ifndef VERSION_FLAVOR
#define VERSION_FLAVOR ""
#endif

#ifdef HAVE_EXTCAP
#include <extcap.h>
#endif

MainWelcome::MainWelcome(QWidget *parent) :
    QFrame(parent),
    welcome_ui_(new Ui::MainWelcome),
    flavor_(tr(VERSION_FLAVOR)),
    #ifdef Q_OS_MAC
    show_in_str_(tr("Show in Finder")),
    #else
    show_in_str_(tr("Show in Folder")),
    #endif
    splash_overlay_(NULL)

{
    welcome_ui_->setupUi(this);

    recent_files_ = welcome_ui_->recentList;

    welcome_ui_->captureFilterComboBox->setEnabled(false);

    QColor hover_color = ColorUtils::alphaBlend(palette().window(), palette().highlight(), 0.5);

    QString welcome_ss = QString(
                "MainWelcome {"
                "  padding: 1em;"
                " }"
                "MainWelcome, QAbstractItemView {"
                "  background-color: palette(base);"
                "  color: palette(text);"
                " }"
                "QAbstractItemView {"
                "  border: 0;"
                "}"
                );
#if !defined(Q_OS_WIN)
    welcome_ss += QString(
                "QAbstractItemView:item:hover {"
                "  background-color: %1;"
                "  color: palette(text);"
                "}"
                )
            .arg(hover_color.name());
#endif
    setStyleSheet(welcome_ss);

    QString banner_ss = QString(
                "QLabel {"
                "  border-radius: 0.33em;"
                "  color: %1;"
                "  background-color: %2;"
                "  padding: 0.33em;"
                "}"
                )
            .arg(QColor(tango_aluminium_6).name())   // Text color
            .arg(QColor(tango_sky_blue_2).name());   // Background color
    welcome_ui_->mainWelcomeBanner->setStyleSheet(banner_ss);

    QString title_button_ss = QString(
            "QLabel {"
            "  color: %1;"
            "}"
            "QLabel::hover {"
            "  color: %2;"
            "}"
            )
            .arg(QColor(tango_aluminium_4).name())   // Text color
            .arg(QColor(tango_sky_blue_4).name());   // Hover color

    // XXX Is there a better term than "flavor"? Provider? Admonition (a la DocBook)?
    // Release_source?
    // Typical use cases are automated builds from wireshark.org and private,
    // not-for-redistribution packages.
    if (flavor_.isEmpty()) {
        welcome_ui_->flavorBanner->hide();
    } else {
        // If needed there are a couple of ways we can make this customizable.
        // - Add one or more classes, e.g. "note" or "warning" similar to
        //   SyntaxLineEdit, which we can then expose vi #defines.
        // - Just expose direct color values via #defines.
        QString flavor_ss = QString(
                    "QLabel {"
                    "  border-radius: 0.25em;"
                    "  color: %1;"
                    "  background-color: %2;"
                    "  padding: 0.25em;"
                    "}"
                    )
                .arg("white") //   Text color
                .arg("#2c4bc4"); // Background color. Matches capture start button.
        //            .arg(QColor(tango_butter_5).name());      // "Warning" background

        welcome_ui_->flavorBanner->setText(flavor_);
        welcome_ui_->flavorBanner->setStyleSheet(flavor_ss);
    }
    welcome_ui_->captureLabel->setStyleSheet(title_button_ss);
    welcome_ui_->recentLabel->setStyleSheet(title_button_ss);
    welcome_ui_->helpLabel->setStyleSheet(title_button_ss);

#ifdef Q_OS_MAC
    recent_files_->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    welcome_ui_->openFrame->hide();
    recent_files_->setStyleSheet(
            "QListWidget::item {"
            "  padding-top: 0.2em;"
            "  padding-bottom: 0.2em;"
            "}"
            "QListWidget::item::first {"
            "  padding-top: 0;"
            "}"
            "QListWidget::item::last {"
            "  padding-bottom: 0;"
            "}"
            );
    recent_files_->setTextElideMode(Qt::ElideLeft);

    recent_ctx_menu_ = new QMenu(this);
    welcome_ui_->recentList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(recent_files_, SIGNAL(customContextMenuRequested(QPoint)),
            this, SLOT(showRecentContextMenu(QPoint)));

    connect(wsApp, SIGNAL(updateRecentCaptureStatus(const QString &, qint64, bool)), this, SLOT(updateRecentCaptures()));
    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(appInitialized()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(itemSelectionChanged()),
            welcome_ui_->captureFilterComboBox, SIGNAL(interfacesChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(typeSelectionChanged()),
                    this, SLOT(interfaceListChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    connect(welcome_ui_->captureFilterComboBox->lineEdit(), SIGNAL(textEdited(QString)),
            this, SLOT(captureFilterTextEdited(QString)));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(pushFilterSyntaxStatus(const QString&)),
            this, SIGNAL(pushFilterSyntaxStatus(const QString&)));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(popFilterSyntaxStatus()),
            this, SIGNAL(popFilterSyntaxStatus()));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(captureFilterSyntaxChanged(bool)),
            this, SIGNAL(captureFilterSyntaxChanged(bool)));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(startCapture()),
            this, SIGNAL(startCapture()));
    connect(recent_files_, SIGNAL(itemActivated(QListWidgetItem *)), this, SLOT(openRecentItem(QListWidgetItem *)));
    updateRecentCaptures();

#if QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    QGraphicsBlurEffect *blur = new QGraphicsBlurEffect(welcome_ui_->childContainer);
    blur->setBlurRadius(2);
    welcome_ui_->childContainer->setGraphicsEffect(blur);
#endif

    splash_overlay_ = new SplashOverlay(this);
}

MainWelcome::~MainWelcome()
{
    delete welcome_ui_;
}

InterfaceFrame *MainWelcome::getInterfaceFrame()
{
    return welcome_ui_->interfaceFrame;
}

const QString MainWelcome::captureFilter()
{
    return welcome_ui_->captureFilterComboBox->currentText();
}

void MainWelcome::setCaptureFilter(const QString capture_filter)
{
    // capture_filter comes from the current filter in
    // CaptureInterfacesDialog. We need to find a good way to handle
    // multiple filters.
    welcome_ui_->captureFilterComboBox->lineEdit()->setText(capture_filter);
}

void MainWelcome::interfaceListChanged()
{
    QString btnText = tr("All interfaces shown");
    if (welcome_ui_->interfaceFrame->interfacesHidden() > 0) {
        btnText = tr("%n interface(s) shown, %1 hidden", "",
                     welcome_ui_->interfaceFrame->interfacesPresent())
                .arg(welcome_ui_->interfaceFrame->interfacesHidden());
    }
    welcome_ui_->btnInterfaceType->setText(btnText);
    welcome_ui_->btnInterfaceType->setMenu(welcome_ui_->interfaceFrame->getSelectionMenu());
}

void MainWelcome::appInitialized()
{
    // XXX Add a "check for updates" link?
    QString full_release = tr("You are running Wireshark ");
    full_release += get_ws_vcs_version_info();
    full_release += tr(".");
#ifdef HAVE_SOFTWARE_UPDATE
    if (prefs.gui_update_enabled) {
        full_release += tr(" You receive automatic updates.");
    } else {
        full_release += tr(" You have disabled automatic updates.");
    }
#else
    // XXX Is there a way to tell if the user installed Wireshark via an
    // external package manager? If so we could say so here. We could
    // also add a link to the download page.
#endif
    welcome_ui_->fullReleaseLabel->setText(full_release);

#if QT_VERSION > QT_VERSION_CHECK(5, 0, 0)
    welcome_ui_->childContainer->setGraphicsEffect(NULL);
#endif

#ifdef HAVE_LIBPCAP
    welcome_ui_->captureFilterComboBox->lineEdit()->setText(global_capture_opts.default_options.cfilter);
#endif // HAVE_LIBPCAP

    welcome_ui_->captureFilterComboBox->setEnabled(true);

    interfaceListChanged();

    welcome_ui_->interfaceFrame->ensureSelectedInterface();

    delete splash_overlay_;
    splash_overlay_ = NULL;
}

#ifdef HAVE_LIBPCAP
// Update each selected device cfilter when the user changes the contents
// of the capture filter lineedit. We do so here so that we don't clobber
// filters set in the Capture Options / Interfaces dialog or ones set via
// the command line.
void MainWelcome::captureFilterTextEdited(const QString capture_filter)
{
    if (global_capture_opts.num_selected > 0) {
        interface_t device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (!device.selected) {
                continue;
            }
            //                if (device.active_dlt == -1) {
            //                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The link type of interface %s was not specified.", device.name);
            //                    continue;  /* Programming error: somehow managed to select an "unsupported" entry */
            //                }
            g_array_remove_index(global_capture_opts.all_ifaces, i);
            g_free(device.cfilter);
            if (capture_filter.isEmpty()) {
                device.cfilter = NULL;
            } else {
                device.cfilter = qstring_strdup(capture_filter);
            }
            g_array_insert_val(global_capture_opts.all_ifaces, i, device);
            //                update_filter_string(device.name, filter_text);
        }
    }
}
#else
// No-op if we don't have capturing.
void MainWelcome::captureFilterTextEdited(const QString)
{
}
#endif

// The interface list selection has changed. At this point the user might
// have entered a filter or we might have pre-filled one from a number of
// sources such as our remote connection, the command line, or a previous
// selection.
// Must not change any interface data.
void MainWelcome::interfaceSelected()
{
    QPair <const QString, bool> sf_pair = CaptureFilterEdit::getSelectedFilter();
    const QString user_filter = sf_pair.first;
    bool conflict = sf_pair.second;

    if (conflict) {
        welcome_ui_->captureFilterComboBox->lineEdit()->clear();
        welcome_ui_->captureFilterComboBox->setConflict(true);
    } else {
        welcome_ui_->captureFilterComboBox->lineEdit()->setText(user_filter);
    }

    // Notify others (capture interfaces dialog) that the selection has changed.
    emit interfacesChanged();
}

#ifdef HAVE_EXTCAP
void MainWelcome::on_interfaceFrame_showExtcapOptions(QString device_name)
{
    emit showExtcapOptions(device_name);
}
#endif

void MainWelcome::on_interfaceFrame_startCapture()
{
    emit startCapture();
}

void MainWelcome::updateRecentCaptures() {
    QString itemLabel;
    QListWidgetItem *rfItem;
    QFont rfFont;
    QString selectedFilename;

    if (!recent_files_->selectedItems().isEmpty()) {
        rfItem = recent_files_->selectedItems().first();
        selectedFilename = rfItem->data(Qt::UserRole).toString();
    }

    if (wsApp->recentItems().count() == 0) {
       // Recent menu has been cleared, remove all recent files.
       while (recent_files_->count()) {
          delete recent_files_->item(0);
       }
    }

    int rfRow = 0;
    foreach (recent_item_status *ri, wsApp->recentItems()) {
        itemLabel = ri->filename;

        if (rfRow >= recent_files_->count()) {
            recent_files_->addItem(itemLabel);
        }

        itemLabel.append(" (");
        if (ri->accessible) {
            if (ri->size/1024/1024/1024 > 10) {
                itemLabel.append(QString("%1 GB").arg(ri->size/1024/1024/1024));
            } else if (ri->size/1024/1024 > 10) {
                itemLabel.append(QString("%1 MB").arg(ri->size/1024/1024));
            } else if (ri->size/1024 > 10) {
                itemLabel.append(QString("%1 KB").arg(ri->size/1024));
            } else {
                itemLabel.append(QString("%1 Bytes").arg(ri->size));
            }
        } else {
            itemLabel.append(tr("not found"));
        }
        itemLabel.append(")");
        rfFont.setItalic(!ri->accessible);
        rfItem = recent_files_->item(rfRow);
        rfItem->setText(itemLabel);
        rfItem->setData(Qt::AccessibleTextRole, itemLabel);
        rfItem->setData(Qt::UserRole, ri->filename);
        rfItem->setFlags(ri->accessible ? Qt::ItemIsSelectable | Qt::ItemIsEnabled : Qt::NoItemFlags);
        rfItem->setFont(rfFont);
        if (ri->filename == selectedFilename) {
            recent_files_->setItemSelected(rfItem, true);
        }
        rfRow++;
    }

    int row = recent_files_->count();
    while (row > 0 && (row > (int) prefs.gui_recent_files_count_max || row > rfRow)) {
        row--;
        delete recent_files_->item(row);
    }
    if (recent_files_->count() > 0) {
        welcome_ui_->openFrame->animatedShow();
    } else {
        welcome_ui_->openFrame->animatedHide();
    }
}

void MainWelcome::openRecentItem(QListWidgetItem *item) {
    QString cfPath = item->data(Qt::UserRole).toString();
    emit recentFileActivated(cfPath);
}

void MainWelcome::resizeEvent(QResizeEvent *event)
{
    if (splash_overlay_)
        splash_overlay_->resize(event->size());
//    event->accept();

    QFrame::resizeEvent(event);
}

void MainWelcome::setCaptureFilterText(const QString capture_filter)
{
    welcome_ui_->captureFilterComboBox->lineEdit()->setText(capture_filter);
    captureFilterTextEdited(capture_filter);
}

void MainWelcome::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            welcome_ui_->retranslateUi(this);
            welcome_ui_->flavorBanner->setText(flavor_);
            interfaceListChanged();
            break;
        default:
            break;
        }
    }
    QFrame::changeEvent(event);
}

void MainWelcome::showRecentContextMenu(QPoint pos)
{
    QListWidgetItem *li = recent_files_->itemAt(pos);
    if (!li) return;

    recent_ctx_menu_->clear();

    QString cf_path = li->data(Qt::UserRole).toString();

    QAction *show_action = recent_ctx_menu_->addAction(show_in_str_);
    show_action->setData(cf_path);
    connect(show_action, SIGNAL(triggered(bool)), this, SLOT(showRecentFolder()));

    QAction *copy_action = recent_ctx_menu_->addAction(tr("Copy file path"));
    copy_action->setData(cf_path);
    connect(copy_action, SIGNAL(triggered(bool)), this, SLOT(copyRecentPath()));

    recent_ctx_menu_->addSeparator();

    QAction *remove_action = recent_ctx_menu_->addAction(tr("Remove"));
    remove_action->setData(cf_path);
    connect(remove_action, SIGNAL(triggered(bool)), this, SLOT(removeRecentPath()));

    recent_ctx_menu_->exec(recent_files_->mapToGlobal(pos));
}

void MainWelcome::showRecentFolder()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    desktop_show_in_folder(cf_path);
}

void MainWelcome::copyRecentPath()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    if (cf_path.isEmpty()) return;

    wsApp->clipboard()->setText(cf_path);
}

void MainWelcome::removeRecentPath()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    if (cf_path.isEmpty()) return;

    wsApp->removeRecentItem(cf_path);
}

void MainWelcome::on_captureLabel_clicked()
{
    wsApp->doTriggerMenuItem(WiresharkApplication::CaptureOptionsDialog);
}

void MainWelcome::on_helpLabel_clicked()
{
    QDesktopServices::openUrl(QUrl(topic_online_url(ONLINEPAGE_DOCS)));
}

void MainWelcome::on_recentLabel_clicked()
{
    wsApp->doTriggerMenuItem(WiresharkApplication::FileOpenDialog);
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
