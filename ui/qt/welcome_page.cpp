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
#include <ui/qt/widgets/capture_card_widget.h>

#include "main_application.h"

#include <QClipboard>
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

WelcomePage::WelcomePage(QWidget *parent) :
    QFrame(parent),
    welcome_ui_(new Ui::WelcomePage),
    #ifdef Q_OS_MAC
    show_in_str_(tr("Show in Finder")),
    #else
    show_in_str_(tr("Show in Folder")),
    #endif
    splash_overlay_(NULL)

{
    welcome_ui_->setupUi(this);

    setContentsMargins(0, 0, 0, 0);
    setAccessibleName(tr("Welcome page"));
    setAccessibleDescription(tr("The %1 welcome page provides access to recent files, capture interfaces, and learning resources.").arg(mainApp->applicationName()));

    welcome_ui_->tipsSectionCard->setVisible(true);

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
    welcome_ui_->openFileSectionRecentList->setAccessibleName(tr("Recent capture files"));
    welcome_ui_->openFileSectionRecentList->setAccessibleDescription(tr("List of recently opened capture files. Double-click or press Enter to open."));
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

    // "Capture" header click opens Capture Options dialog
    if (auto *captureHeader = welcome_ui_->captureSectionCard->findChild<ClickableLabel*>(QStringLiteral("captureHeader"))) {
        connect(captureHeader, &ClickableLabel::clicked, this, []() {
            mainApp->doTriggerMenuItem(MainApplication::CaptureOptionsDialog);
        });
    }

    splash_overlay_ = new SplashOverlay(this);
}

WelcomePage::~WelcomePage()
{
    delete welcome_ui_;
}

InterfaceFrame *WelcomePage::getInterfaceFrame()
{
    return welcome_ui_->captureSectionCard->interfaceFrame();
}

CaptureCardWidget *WelcomePage::captureCard()
{
    return welcome_ui_->captureSectionCard;
}

const QString WelcomePage::captureFilter()
{
    return welcome_ui_->captureSectionCard->captureFilter();
}

void WelcomePage::setCaptureFilter(const QString capture_filter)
{
    welcome_ui_->captureSectionCard->setCaptureFilter(capture_filter);
}

void WelcomePage::setCaptureFilterText(const QString capture_filter)
{
    welcome_ui_->captureSectionCard->setCaptureFilterText(capture_filter);
}

void WelcomePage::interfaceSelected()
{
    welcome_ui_->captureSectionCard->interfaceSelected();
}

void WelcomePage::appInitialized()
{
    applySidebarPreferences();

    splash_overlay_->fadeOut();
    splash_overlay_ = NULL;

    // Ensure sidebar layout adapts to the restored window size.
    // resizeEvent may have fired before the layout was finalized.
    updateSidebarLayout();
}

void WelcomePage::applySidebarPreferences()
{
    // There are slides that will be shown EVEN if the section card is set hidden through the preferences.
    // hasVisibleSlides() checks if there are any slides that should be shown, as well as the user's preferences.
    bool slidesAreVisible = welcome_ui_->tipsSectionCard->hasVisibleSlides();

    welcome_ui_->tipsSectionCard->setSlideDeckFreeze(true);
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerEvents, recent.gui_welcome_page_sidebar_tips_events);
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerSponsorship, recent.gui_welcome_page_sidebar_tips_sponsorship);
    welcome_ui_->tipsSectionCard->setSlideTypeVisible(BannerTips, recent.gui_welcome_page_sidebar_tips_tips);
    welcome_ui_->tipsSectionCard->setSlidesTest(recent.gui_welcome_page_sidebar_tips_slides_test);
    welcome_ui_->tipsSectionCard->setSlideDeckFreeze(false);
    welcome_ui_->tipsSectionCard->setAutoAdvance(recent.gui_welcome_page_sidebar_tips_auto_advance);
    welcome_ui_->tipsSectionCard->setAutoAdvanceInterval(recent.gui_welcome_page_sidebar_tips_interval);
    welcome_ui_->tipsSectionCard->setVisible(slidesAreVisible);

    welcome_ui_->learnSectionCard->setVisible(recent.gui_welcome_page_sidebar_learn_visible);

    // Hide the entire sidebar container when all sidebar widgets are disabled,
    // so the main content area can expand to fill the full window width.
    bool sidebar_visible = slidesAreVisible || recent.gui_welcome_page_sidebar_learn_visible;
    welcome_ui_->sidebarContainer->setVisible(sidebar_visible);
}

bool WelcomePage::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
    {
        updateStyleSheets();
        break;
    }
    case QEvent::LanguageChange:
    {
        welcome_ui_->retranslateUi(this);
        break;
    }
    default:
        break;

    }
    return QFrame::event(event);
}

void WelcomePage::resizeEvent(QResizeEvent *event)
{
    if (splash_overlay_)
        splash_overlay_->resize(event->size());

    QFrame::resizeEvent(event);

    updateSidebarLayout();
}

void WelcomePage::showEvent(QShowEvent *event)
{
    QFrame::showEvent(event);

    // The final window geometry may not be known until the widget is shown
    // (especially on macOS with restored window positions). Ensure the
    // sidebar layout adapts to the actual available space.
    updateSidebarLayout();
}

/*
 * Adapts the sidebar widget states to the available vertical space.
 *
 * The sidebar contains two widgets stacked vertically with spacing between
 * them: the InfoBannerWidget (tips/sponsors) and the LearnCardWidget (docs
 * links + action buttons). Both support a compact mode to reduce their
 * height when the window is small.
 *
 * Collapse order (as the window shrinks):
 *   1. LearnCardWidget links collapse (vertical list -> horizontal row)
 *   2. InfoBannerWidget compacts (hides illustration and body text)
 *
 * Expand order (as the window grows) is the reverse:
 *   1. InfoBannerWidget expands back to full
 *   2. LearnCardWidget links expand back to vertical
 *
 * All size values are queried from the widgets and layout, not hardcoded:
 *   - tipsFull:  InfoBannerWidget::sizeHint().height()
 *                Always returns the full preferred height (360) regardless
 *                of compact state. This is stable because sizeHint()
 *                reports what the widget *wants*, while compact mode is
 *                enforced via setMaximumHeight().
 *   - learnMax:  LearnCardWidget::maximumHeight()  (from .ui: 240)
 *   - learnMin:  LearnCardWidget::minimumHeight()   (from .ui: 110)
 *   - spacing:   sidebarLayout->spacing()            (from .ui: 16)
 *
 * Hysteresis (kHysteresis = 20px):
 *   Without hysteresis, at the exact collapse threshold the layout
 *   oscillates: collapsing a widget frees space, which satisfies the
 *   expand threshold, which expands, which exceeds the threshold again.
 *   On each resize event this cycle repeats, causing visible flickering.
 *
 *   Hysteresis adds a dead zone between collapse and expand thresholds.
 *   A widget collapses at threshold T but only re-expands at T + 20.
 *   In the 20px gap, the current state is preserved.
 *
 *   The value 20px was chosen empirically: it must be large enough that
 *   the layout geometry change from collapsing/expanding a widget (which
 *   can shift available height by a few pixels due to rounding, spacing,
 *   and platform differences) doesn't cross back over the threshold. In
 *   practice, resize events during a user drag arrive ~8-12px apart, so
 *   20px ensures at least one stable frame at the boundary. A larger
 *   value would delay the transition visibly; a smaller one risks not
 *   fully suppressing the oscillation on high-DPI displays where pixel
 *   increments are coarser.
 *
 * Decision zones (with current widget sizes):
 *
 *   available >= 636 (linksExpandAt)
 *     -> full tips + expanded links
 *
 *   available >= 506 (tipsExpandAt)  and  < 636
 *     -> full tips + collapsed links
 *     (between 616-635: hysteresis zone for links -- keeps current state
 *      if already expanded, won't re-expand if collapsed)
 *
 *   available >= 486 (tipsCompactAt)  and  < 506
 *     -> hysteresis zone for tips -- keeps current tips state,
 *       links forced collapsed
 *
 *   available < 486 (tipsCompactAt)
 *     -> compact tips + collapsed links
 *
 * Called from: resizeEvent(), showEvent(), appInitialized(), and
 * indirectly via updateGeometry() when the welcome header banner
 * visibility changes.
 */
void WelcomePage::updateSidebarLayout()
{
    int available = welcome_ui_->sidebarContainer->height();
    if (available <= 0)
        return;

    static const int kHysteresis = 20;

    int spacing = welcome_ui_->sidebarLayout->spacing();
    int tipsFull = welcome_ui_->tipsSectionCard->sizeHint().height();
    int learnMax = welcome_ui_->learnSectionCard->maximumHeight();
    int learnMin = welcome_ui_->learnSectionCard->minimumHeight();

    // Collapse threshold: the minimum available height to show this state.
    // Expand threshold: collapse + hysteresis -- prevents oscillation.

    // Level 1: links collapse when full tips + expanded learn don't fit.
    int linksCollapseAt = tipsFull + spacing + learnMax;
    int linksExpandAt = linksCollapseAt + kHysteresis;

    // Level 2: tips compact when full tips + collapsed learn don't fit.
    int tipsCompactAt = tipsFull + spacing + learnMin;
    int tipsExpandAt = tipsCompactAt + kHysteresis;

    bool collapseLinks = welcome_ui_->learnSectionCard->isLinksCollapsed();
    bool compactTips = welcome_ui_->tipsSectionCard->isCompactMode();

    if (available >= linksExpandAt) {
        collapseLinks = false;
        compactTips = false;
    } else if (available >= tipsExpandAt) {
        collapseLinks = true;
        compactTips = false;
    } else if (available >= tipsCompactAt) {
        collapseLinks = true;
        // tips state preserved (hysteresis zone)
    } else {
        collapseLinks = true;
        compactTips = true;
    }

    welcome_ui_->learnSectionCard->setLinksCollapsed(collapseLinks);
    welcome_ui_->tipsSectionCard->setCompactMode(compactTips);
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

void WelcomePage::updateStyleSheets()
{
    QString welcome_ss = QStringLiteral(
                "WelcomePage {"
                "  padding: 0;"
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

    /* LearnCardWidget and CaptureCardWidget manage their own stylesheets */
}

void WelcomePage::on_openFileSectionLabel_clicked()
{
    mainApp->doTriggerMenuItem(MainApplication::FileOpenDialog);
}
