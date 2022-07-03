/* welcome_page.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>

#include "ui/capture_globals.h"
#include "ui/urls.h"

#include "ui/version_info.h"

#include "welcome_page.h"
#include <ui_welcome_page.h>
#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include "main_application.h"

#include <QClipboard>
#include <QDate>
#include <QDesktopServices>
#include <QDir>
#include <QListWidget>
#include <QMenu>
#include <QResizeEvent>
#include <QUrl>
#include <QWidget>

#ifndef VERSION_FLAVOR
#define VERSION_FLAVOR ""
#endif

#include <extcap.h>

WelcomePage::WelcomePage(QWidget *parent) :
    QFrame(parent),
    welcome_ui_(new Ui::WelcomePage),
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

    welcome_ui_->mainWelcomeBanner->setText(tr("Welcome to %1").arg(mainApp->applicationName()));

    updateStyleSheets();


#ifdef Q_OS_MAC
    recent_files_->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    welcome_ui_->openFrame->hide();
    recent_files_->setTextElideMode(Qt::ElideLeft);

    welcome_ui_->recentList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(recent_files_, SIGNAL(customContextMenuRequested(QPoint)),
            this, SLOT(showRecentContextMenu(QPoint)));

    connect(mainApp, SIGNAL(updateRecentCaptureStatus(const QString &, qint64, bool)), this, SLOT(updateRecentCaptures()));
    connect(mainApp, SIGNAL(appInitialized()), this, SLOT(appInitialized()));
    connect(mainApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(itemSelectionChanged()),
            welcome_ui_->captureFilterComboBox, SIGNAL(interfacesChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(typeSelectionChanged()),
                    this, SLOT(interfaceListChanged()));
    connect(welcome_ui_->interfaceFrame, SIGNAL(itemSelectionChanged()), this, SLOT(interfaceSelected()));
    connect(welcome_ui_->captureFilterComboBox->lineEdit(), SIGNAL(textEdited(QString)),
            this, SLOT(captureFilterTextEdited(QString)));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(captureFilterSyntaxChanged(bool)),
            this, SIGNAL(captureFilterSyntaxChanged(bool)));
    connect(welcome_ui_->captureFilterComboBox, SIGNAL(startCapture()),
            this, SLOT(captureStarting()));
    connect(recent_files_, SIGNAL(itemActivated(QListWidgetItem *)), this, SLOT(openRecentItem(QListWidgetItem *)));
    updateRecentCaptures();

    splash_overlay_ = new SplashOverlay(this);
}

WelcomePage::~WelcomePage()
{
    delete welcome_ui_;
}

InterfaceFrame *WelcomePage::getInterfaceFrame()
{
    return welcome_ui_->interfaceFrame;
}

const QString WelcomePage::captureFilter()
{
    return welcome_ui_->captureFilterComboBox->currentText();
}

void WelcomePage::setCaptureFilter(const QString capture_filter)
{
    // capture_filter comes from the current filter in
    // CaptureInterfacesDialog. We need to find a good way to handle
    // multiple filters.
    welcome_ui_->captureFilterComboBox->lineEdit()->setText(capture_filter);
}

void WelcomePage::interfaceListChanged()
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

void WelcomePage::setReleaseLabel()
{
    // XXX Add a "check for updates" link?
    QString full_release;
    QDate today = QDate::currentDate();
    if ((today.month() == 4 && today.day() == 1) || (today.month() == 7 && today.day() == 14)) {
        full_release = tr("You are sniffing the glue that holds the Internet together using Wireshark ");
    } else {
        full_release = tr("You are running Wireshark ");
    }
    full_release += get_ws_vcs_version_info();
    full_release += ".";
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
}

void WelcomePage::appInitialized()
{
    setReleaseLabel();

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
void WelcomePage::captureFilterTextEdited(const QString capture_filter)
{
    if (global_capture_opts.num_selected > 0) {
        interface_t *device;

        for (guint i = 0; i < global_capture_opts.all_ifaces->len; i++) {
            device = &g_array_index(global_capture_opts.all_ifaces, interface_t, i);
            if (!device->selected) {
                continue;
            }
            //                if (device->active_dlt == -1) {
            //                    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The link type of interface %s was not specified.", device->name);
            //                    continue;  /* Programming error: somehow managed to select an "unsupported" entry */
            //                }
            g_free(device->cfilter);
            if (capture_filter.isEmpty()) {
                device->cfilter = NULL;
            } else {
                device->cfilter = qstring_strdup(capture_filter);
            }
            //                update_filter_string(device->name, filter_text);
        }
    }
}
#else
// No-op if we don't have capturing.
void WelcomePage::captureFilterTextEdited(const QString)
{
}
#endif

// The interface list selection has changed. At this point the user might
// have entered a filter or we might have pre-filled one from a number of
// sources such as our remote connection, the command line, or a previous
// selection.
// Must not change any interface data.
void WelcomePage::interfaceSelected()
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

    // Notify others (capture options dialog) that the selection has changed.
    emit interfacesChanged();
}

bool WelcomePage::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        updateStyleSheets();
        break;
    default:
        break;

    }
    return QFrame::event(event);
}

void WelcomePage::on_interfaceFrame_showExtcapOptions(QString device_name, bool startCaptureOnClose)
{
    emit showExtcapOptions(device_name, startCaptureOnClose);
}

void WelcomePage::on_interfaceFrame_startCapture(QStringList ifaces)
{
    emit startCapture(ifaces);
}

void WelcomePage::captureStarting()
{
    welcome_ui_->interfaceFrame->ensureSelectedInterface();
    emit startCapture(QStringList());
}

void WelcomePage::updateRecentCaptures() {
    QString itemLabel;
    QListWidgetItem *rfItem;
    QFont rfFont;
    QString selectedFilename;

    if (!recent_files_->selectedItems().isEmpty()) {
        rfItem = recent_files_->selectedItems().first();
        selectedFilename = rfItem->data(Qt::UserRole).toString();
    }

    if (mainApp->recentItems().count() == 0) {
       // Recent menu has been cleared, remove all recent files.
       while (recent_files_->count()) {
          delete recent_files_->item(0);
       }
    }

    int rfRow = 0;
    foreach (recent_item_status *ri, mainApp->recentItems()) {
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
            rfItem->setSelected(true);
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

void WelcomePage::openRecentItem(QListWidgetItem *item) {
    QString cfPath = item->data(Qt::UserRole).toString();
    emit recentFileActivated(cfPath);
}

void WelcomePage::resizeEvent(QResizeEvent *event)
{
    if (splash_overlay_)
        splash_overlay_->resize(event->size());
//    event->accept();

    QFrame::resizeEvent(event);
}

void WelcomePage::setCaptureFilterText(const QString capture_filter)
{
    welcome_ui_->captureFilterComboBox->lineEdit()->setText(capture_filter);
    captureFilterTextEdited(capture_filter);
}

void WelcomePage::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            welcome_ui_->retranslateUi(this);
            welcome_ui_->flavorBanner->setText(flavor_);
            interfaceListChanged();
            setReleaseLabel();
            break;
        default:
            break;
        }
    }
    QFrame::changeEvent(event);
}

void WelcomePage::showRecentContextMenu(QPoint pos)
{
    QListWidgetItem *li = recent_files_->itemAt(pos);
    if (!li) return;

    QMenu *recent_ctx_menu = new QMenu(this);
    recent_ctx_menu->setAttribute(Qt::WA_DeleteOnClose);

    QString cf_path = li->data(Qt::UserRole).toString();

    QAction *show_action = recent_ctx_menu->addAction(show_in_str_);
    show_action->setData(cf_path);
    connect(show_action, SIGNAL(triggered(bool)), this, SLOT(showRecentFolder()));

    QAction *copy_action = recent_ctx_menu->addAction(tr("Copy file path"));
    copy_action->setData(cf_path);
    connect(copy_action, SIGNAL(triggered(bool)), this, SLOT(copyRecentPath()));

    recent_ctx_menu->addSeparator();

    QAction *remove_action = recent_ctx_menu->addAction(tr("Remove from list"));
    remove_action->setData(cf_path);
    connect(remove_action, SIGNAL(triggered(bool)), this, SLOT(removeRecentPath()));

    recent_ctx_menu->popup(recent_files_->mapToGlobal(pos));
}

void WelcomePage::showRecentFolder()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    if (cf_path.isEmpty()) return;

    desktop_show_in_folder(cf_path);
}

void WelcomePage::copyRecentPath()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    if (cf_path.isEmpty()) return;

    mainApp->clipboard()->setText(cf_path);
}

void WelcomePage::removeRecentPath()
{
    QAction *ria = qobject_cast<QAction*>(sender());
    if (!ria) return;

    QString cf_path = ria->data().toString();
    if (cf_path.isEmpty()) return;

    mainApp->removeRecentItem(cf_path);
}

void WelcomePage::on_captureLabel_clicked()
{
    mainApp->doTriggerMenuItem(MainApplication::CaptureOptionsDialog);
}

void WelcomePage::on_helpLabel_clicked()
{
    QDesktopServices::openUrl(QUrl(WS_DOCS_URL));
}

void WelcomePage::updateStyleSheets()
{
    QString welcome_ss = QString(
                "WelcomePage {"
                "  padding: 1em;"
                " }"
                "WelcomePage, QAbstractItemView {"
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
            .arg(ColorUtils::hoverBackground().name(QColor::HexArgb));
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

    // The helpLinks markup includes its own <style>...</style> section.
    // Replacing it with a stylesheet and reapplying it like we do above
    // doesn't work, but this does.
    QString hl_text = welcome_ui_->helpLinks->text();
    welcome_ui_->helpLinks->clear();
    welcome_ui_->helpLinks->setText(hl_text);
}

void WelcomePage::on_recentLabel_clicked()
{
    mainApp->doTriggerMenuItem(MainApplication::FileOpenDialog);
}
