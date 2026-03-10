/* welcome_page.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/prefs.h>

#include "ui/capture_globals.h"
#include "ui/recent.h"
#include "ui/urls.h"

#include <app/application_flavor.h>

#include "welcome_page.h"
#include <ui_welcome_page.h>
#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/utils/color_utils.h>
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/models/recentcapturefiles_list_model.h>
#include <ui/qt/utils/workspace_state.h>
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

    welcome_ui_->tipsSectionCard->setVisible(true);

    welcome_ui_->captureSectionFilterComboBox->setEnabled(false);

    welcome_ui_->titleSectionBannerLabel->setText(tr("Welcome to %1").arg(mainApp->applicationName()));

    updateStyleSheets();

    /* Handle Recent Capture Files List */
    // In welcome_page.cpp or wherever the list is created
    auto *model = new RecentCaptureFilesListModel(this);
    auto *proxyModel = new RecentCaptureFilesReverseProxyModel(this);
    proxyModel->setSourceModel(model);

    welcome_ui_->openFileSectionRecentList->setVisible(true);
    welcome_ui_->openFileSectionRecentList->setModel(proxyModel);
    welcome_ui_->openFileSectionRecentList->setItemDelegate(new RecentCaptureFilesDelegate(welcome_ui_->openFileSectionRecentList));
    welcome_ui_->openFileSectionRecentList->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(welcome_ui_->openFileSectionRecentList, &QListView::activated,
        this, [this]() {
            QModelIndex index = welcome_ui_->openFileSectionRecentList->currentIndex();
            if (index.isValid()) {
                QString cfile = index.data(RecentCaptureFilesListModel::FilenameRole).toString();
                emit recentFileActivated(cfile);
            }
        });
    connect(welcome_ui_->openFileSectionRecentList, &QListView::customContextMenuRequested,
        this, &WelcomePage::showCaptureFilesContextMenu);

    if (WorkspaceState::instance()->recentCaptureFiles().size() > 0) {
        welcome_ui_->openFileSectionLabel->setVisible(true);
        welcome_ui_->openFileSectionRecentList->setVisible(true);
    } else {
        welcome_ui_->openFileSectionLabel->setVisible(false);
        welcome_ui_->openFileSectionRecentList->setVisible(false);
    }

#ifdef Q_OS_MAC
    welcome_ui_->openFileSectionRecentList->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    welcome_ui_->openFileSectionRecentList->setTextElideMode(Qt::ElideLeft);

    connect(mainApp, &MainApplication::appInitialized, this, &WelcomePage::appInitialized);
    connect(mainApp, &MainApplication::preferencesChanged, this, &WelcomePage::applySidebarPreferences);
    connect(mainApp, &MainApplication::localInterfaceListChanged, this, &WelcomePage::interfaceListChanged);
#ifdef HAVE_LIBPCAP
    connect(mainApp, &MainApplication::scanLocalInterfaces,
            welcome_ui_->captureSectionInterfaceFrame, &InterfaceFrame::scanLocalInterfaces);
#endif
    connect(welcome_ui_->captureSectionInterfaceFrame, &InterfaceFrame::itemSelectionChanged,
            welcome_ui_->captureSectionFilterComboBox, &CaptureFilterCombo::interfacesChanged);
    connect(welcome_ui_->captureSectionInterfaceFrame, &InterfaceFrame::typeSelectionChanged,
                    this, &WelcomePage::interfaceListChanged);
    connect(welcome_ui_->captureSectionInterfaceFrame, &InterfaceFrame::itemSelectionChanged, this, &WelcomePage::interfaceSelected);
    connect(welcome_ui_->captureSectionFilterComboBox->lineEdit(), &QLineEdit::textEdited,
            this, &WelcomePage::captureFilterTextEdited);
    connect(welcome_ui_->captureSectionFilterComboBox, &CaptureFilterCombo::captureFilterSyntaxChanged,
            this, &WelcomePage::captureFilterSyntaxChanged);
    connect(welcome_ui_->captureSectionFilterComboBox, &CaptureFilterCombo::startCapture,
            this, &WelcomePage::captureStarting);

    splash_overlay_ = new SplashOverlay(this);
}

WelcomePage::~WelcomePage()
{
    delete welcome_ui_;
}

InterfaceFrame *WelcomePage::getInterfaceFrame()
{
    return welcome_ui_->captureSectionInterfaceFrame;
}

const QString WelcomePage::captureFilter()
{
    return welcome_ui_->captureSectionFilterComboBox->currentText();
}

void WelcomePage::setCaptureFilter(const QString capture_filter)
{
    // capture_filter comes from the current filter in
    // CaptureInterfacesDialog. We need to find a good way to handle
    // multiple filters.
    welcome_ui_->captureSectionFilterComboBox->lineEdit()->setText(capture_filter);
}

void WelcomePage::interfaceListChanged()
{
    QString btnText = tr("All interfaces shown");
    if (welcome_ui_->captureSectionInterfaceFrame->interfacesHidden() > 0) {
        btnText = tr("%n interface(s) shown, %1 hidden", "",
                     welcome_ui_->captureSectionInterfaceFrame->interfacesPresent())
                .arg(welcome_ui_->captureSectionInterfaceFrame->interfacesHidden());
    }
    welcome_ui_->captureSectionInterfaceTypeButton->setText(btnText);
    welcome_ui_->captureSectionInterfaceTypeButton->setMenu(welcome_ui_->captureSectionInterfaceFrame->getSelectionMenu());
}

QString WelcomePage::getReleaseLabel()
{
    return tr("You are running Wireshark ");
}

QString WelcomePage::getReleaseLabelGlue()
{
    return tr("You are sniffing the glue that holds the Internet together using Wireshark ");
}

void WelcomePage::setReleaseLabel()
{
    // XXX Add a "check for updates" link?
    QString full_release;
    QDate today = QDate::currentDate();
    if ((today.month() == 4 && today.day() == 1) || (today.month() == 7 && today.day() == 14)) {
        full_release = getReleaseLabelGlue();
    } else {
        full_release = getReleaseLabel();
    }
    full_release += application_get_vcs_version_info();
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
    welcome_ui_->titleSectionVersionLabel->setText(full_release);
}

void WelcomePage::appInitialized()
{
    setReleaseLabel();
    applySidebarPreferences();

#ifdef HAVE_LIBPCAP
    welcome_ui_->captureSectionFilterComboBox->lineEdit()->setText(global_capture_opts.default_options.cfilter);
#endif // HAVE_LIBPCAP

    welcome_ui_->captureSectionFilterComboBox->setEnabled(true);

    interfaceListChanged();

    welcome_ui_->captureSectionInterfaceFrame->ensureSelectedInterface();

    splash_overlay_->fadeOut();
    splash_overlay_ = NULL;
}

void WelcomePage::applySidebarPreferences()
{
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerEvents, recent.gui_welcome_page_sidebar_tips_events);
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerSponsorship, recent.gui_welcome_page_sidebar_tips_sponsorship);
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerTips, recent.gui_welcome_page_sidebar_tips_tips);
    welcome_ui_->tipsSectionCard->setAutoAdvanceInterval(recent.gui_welcome_page_sidebar_tips_interval);
    welcome_ui_->tipsSectionCard->setVisible(recent.gui_welcome_page_sidebar_tips_visible);

    welcome_ui_->learnSectionCard->setVisible(recent.gui_welcome_page_sidebar_learn_visible);
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

        for (unsigned i = 0; i < global_capture_opts.all_ifaces->len; i++) {
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
        welcome_ui_->captureSectionFilterComboBox->lineEdit()->clear();
        welcome_ui_->captureSectionFilterComboBox->setConflict(true);
    } else {
        welcome_ui_->captureSectionFilterComboBox->lineEdit()->setText(user_filter);
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

void WelcomePage::on_captureSectionInterfaceFrame_showExtcapOptions(QString device_name, bool startCaptureOnClose)
{
    emit showExtcapOptions(device_name, startCaptureOnClose);
}

void WelcomePage::on_captureSectionInterfaceFrame_startCapture(QStringList ifaces)
{
    emit startCapture(ifaces);
}

void WelcomePage::captureStarting()
{
    welcome_ui_->captureSectionInterfaceFrame->ensureSelectedInterface();
    emit startCapture(QStringList());
}

void WelcomePage::resizeEvent(QResizeEvent *event)
{
    if (splash_overlay_)
        splash_overlay_->resize(event->size());

    QFrame::resizeEvent(event);

    updateSidebarLayout();
}

void WelcomePage::updateSidebarLayout()
{
    int available = welcome_ui_->sidebarContainer->height();
    if (available <= 0)
        return;

    // Sidebar content: InfoBanner + spacing(16) + LearnCard (expands to fill)
    // Full:   360 + 16 + 240 = 616
    // Medium: 360 + 16 + 112 = 488
    const int kFullNeeded = 616;
    const int kMediumNeeded = 488;

    if (available >= kFullNeeded) {
        welcome_ui_->learnSectionCard->setLinksCollapsed(false);
        welcome_ui_->tipsSectionCard->setCompactMode(false);
    } else if (available >= kMediumNeeded) {
        welcome_ui_->learnSectionCard->setLinksCollapsed(true);
        welcome_ui_->tipsSectionCard->setCompactMode(false);
    } else {
        welcome_ui_->learnSectionCard->setLinksCollapsed(true);
        welcome_ui_->tipsSectionCard->setCompactMode(true);
    }
}

void WelcomePage::setCaptureFilterText(const QString capture_filter)
{
    welcome_ui_->captureSectionFilterComboBox->lineEdit()->setText(capture_filter);
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
            welcome_ui_->titleSectionFlavorLabel->setText(flavor_);
            interfaceListChanged();
            setReleaseLabel();
            break;
        default:
            break;
        }
    }
    QFrame::changeEvent(event);
}

void WelcomePage::showCaptureFilesContextMenu(QPoint pos)
{
    QModelIndex index = welcome_ui_->openFileSectionRecentList->indexAt(pos);
    if (!index.isValid()) return;

    QMenu *recent_ctx_menu = new QMenu(this);
    recent_ctx_menu->setAttribute(Qt::WA_DeleteOnClose);

    QModelIndex sourceIndex = static_cast<QSortFilterProxyModel*>(welcome_ui_->openFileSectionRecentList->model())->mapToSource(index);
    RecentCaptureFilesListModel *model = static_cast<RecentCaptureFilesListModel*>(
        static_cast<QSortFilterProxyModel*>(welcome_ui_->openFileSectionRecentList->model())->sourceModel());

    QString filePath = model->data(sourceIndex, RecentCaptureFilesListModel::FilenameRole).toString();
    bool accessible = model->data(sourceIndex, RecentCaptureFilesListModel::AccessibleRole).toBool();

    QAction *show_action = recent_ctx_menu->addAction(show_in_str_);
    show_action->setEnabled(accessible);
    connect(show_action, &QAction::triggered, this, [filePath]{ desktop_show_in_folder(filePath); });

    QAction *copy_action = recent_ctx_menu->addAction(tr("Copy file path"));
    connect(copy_action, &QAction::triggered, this, [filePath]{ mainApp->clipboard()->setText(filePath); });

    recent_ctx_menu->addSeparator();

    QAction *remove_action = recent_ctx_menu->addAction(tr("Remove from list"));
    connect(remove_action, &QAction::triggered, this, [filePath]{
        WorkspaceState::instance()->removeRecentCaptureFile(filePath);
    });

    recent_ctx_menu->popup(welcome_ui_->openFileSectionRecentList->viewport()->mapToGlobal(pos));
}

void WelcomePage::on_captureSectionLabel_clicked()
{
    mainApp->doTriggerMenuItem(MainApplication::CaptureOptionsDialog);
}


void WelcomePage::updateStyleSheets()
{
    QString welcome_ss = QStringLiteral(
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
    welcome_ss += QStringLiteral(
                "QAbstractItemView:item:hover {"
                "  background-color: %1;"
                "  color: palette(text);"
                "}"
                )
            .arg(ColorUtils::hoverBackground().name(QColor::HexArgb));
#endif
    setStyleSheet(welcome_ss);

    QString banner_ss = QStringLiteral(
                "QLabel {"
                "  border-radius: 0.33em;"
                "  color: %1;"
                "  background-color: %2;"
                "  padding: 0.33em;"
                "}"
                )
            .arg(QColor(tango_aluminium_6).name())   // Text color
            .arg(QColor(tango_sky_blue_2).name());   // Background color
    welcome_ui_->titleSectionBannerLabel->setStyleSheet(banner_ss);

    QString title_button_ss = QStringLiteral(
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
        welcome_ui_->titleSectionFlavorLabel->hide();
    } else {
        // If needed there are a couple of ways we can make this customizable.
        // - Add one or more classes, e.g. "note" or "warning" similar to
        //   SyntaxLineEdit, which we can then expose vi #defines.
        // - Just expose direct color values via #defines.
        QString flavor_ss = QStringLiteral(
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

        welcome_ui_->titleSectionFlavorLabel->setText(flavor_);
        welcome_ui_->titleSectionFlavorLabel->setStyleSheet(flavor_ss);
    }
    welcome_ui_->captureSectionLabel->setStyleSheet(title_button_ss);
    welcome_ui_->openFileSectionLabel->setStyleSheet(title_button_ss);

    welcome_ui_->openFileSectionRecentList->setStyleSheet(
            "QListView::item {"
            "  padding-top: 0.2em;"
            "  padding-bottom: 0.2em;"
            "}"
            "QListView::item::first {"
            "  padding-top: 0;"
            "}"
            "QListView::item::last {"
            "  padding-bottom: 0;"
            "}"
            );

    welcome_ui_->tipsSectionCard->updateStyleSheets();

    welcome_ui_->learnSectionCard->updateStyleSheets(
            QColor(tango_aluminium_4), QColor(tango_sky_blue_4));
}

void WelcomePage::on_openFileSectionLabel_clicked()
{
    mainApp->doTriggerMenuItem(MainApplication::FileOpenDialog);
}
