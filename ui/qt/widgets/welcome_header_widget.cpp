/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/widgets/welcome_header_widget.h"
#include <ui_welcome_header_widget.h>

#include <app/application_flavor.h>
#include <epan/prefs.h>

#include <ui/qt/main_application.h>
#include <ui/qt/utils/software_update.h>
#include <ui/qt/utils/theme_manager.h>

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDesktopServices>
#include <QUrl>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>

WelcomeHeaderWidget::WelcomeHeaderWidget(QWidget *parent) :
    QWidget(parent),
    header_ui_(new Ui::WelcomeHeaderWidget)
{
    header_ui_->setupUi(this);
    updateStyleSheet();

    // Rebuild the stylesheet whenever the theme (or its light/dark
    // selection) changes.  QEvent::ApplicationPaletteChange alone isn't
    // reliable here — it only fires when the QPalette actually differs,
    // and a light/dark flip on a theme with no palette overrides may not
    // change any palette roles this widget's gradient depends on.
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &WelcomeHeaderWidget::updateStyleSheet);

    // TODO REMOVE BEFORE COMITTING!!!
    new_version_ = "5.0.0";
    release_notes_ = "https://www.wireshark.org/docs/relnotes/";

    // Setting the application name in the header
    header_ui_->headerTitle->setText(mainApp->applicationName());

    // Setting the version information
    QString vcsInfo = application_get_vcs_version_info_short();
    QString versionText = application_version();
    if (!vcsInfo.isEmpty() || !(versionText.compare(vcsInfo) == 0)) {
        versionText += " (" + vcsInfo + ")";
    }
    header_ui_->headerVersion->setText(versionText);

    // Setting the build label information
    QString buildLabel = tr(VERSION_FLAVOR);
    if (buildLabel.isEmpty())
        header_ui_->headerBuildLabel->hide();
    else
        header_ui_->headerBuildLabel->setText(buildLabel);

    // Connecting software update mechanism. The real information if we are allowed to do the update is only available AFTER
    // the main app has initialized, so we need to connect to the appInitialized signal to update the UI with the correct information.
    header_ui_->updateHeader->setVisible(false);
    if (SoftwareUpdate::plattformSupported()) {
        connect(SoftwareUpdate::instance(), &SoftwareUpdate::updateAvailable, this, &WelcomeHeaderWidget::setAvailableUpdateVersion);
        connect(SoftwareUpdate::instance(), &SoftwareUpdate::updateEngaged, this, &WelcomeHeaderWidget::clearAvailableUpdateVersion);
        connect(mainApp, &MainApplication::appInitialized, this, &WelcomeHeaderWidget::updateSoftwareUpdateInfo);

        // Add the update button
        connect(header_ui_->updateDownload, &QPushButton::clicked, this, []() {
                SoftwareUpdate::instance()->performUIUpdate();
            });

        // Add the skip button
        connect(header_ui_->updateDismiss, &QToolButton::clicked, this, [this]() {
                skipThisVersion();
            });

        // Add the pulse animation to the update dot
        auto *effect = new QGraphicsOpacityEffect(header_ui_->updateDot);
        header_ui_->updateDot->setGraphicsEffect(effect);

        pulseAnimation_ = new QPropertyAnimation(effect, "opacity", this);
        pulseAnimation_->setDuration(2000);
        pulseAnimation_->setStartValue(1.0);
        pulseAnimation_->setKeyValueAt(0.5, 0.3);
        pulseAnimation_->setEndValue(1.0);
        pulseAnimation_->setEasingCurve(QEasingCurve::InOutSine);
        pulseAnimation_->setLoopCount(-1);
    }
}

WelcomeHeaderWidget::~WelcomeHeaderWidget()
{
    delete header_ui_;
}

void WelcomeHeaderWidget::updateSoftwareUpdateInfo()
{
    if (!SoftwareUpdate::plattformSupported())
        return;

    if (new_version_.isEmpty() || skipped_versions_.contains(new_version_)) {
        pulseAnimation_->stop();
        header_ui_->updateHeader->setVisible(false);
        updateGeometry();
        return;
    }

    header_ui_->updateText->setText(tr("Update available: %1").arg(new_version_));
    header_ui_->updateHeader->setVisible(true);
    updateGeometry();
    pulseAnimation_->start();

    // Set accessible text with version context for screen readers
    header_ui_->updateText->setAccessibleName(tr("Update %1 is available").arg(new_version_));
    header_ui_->updateText->setAccessibleDescription(
        tr("A new update for version %1 is available (current version is %2)")
            .arg(new_version_, application_version()));
    header_ui_->updateReleaseNotes->setAccessibleName(tr("Release Notes for update %1").arg(new_version_));
    header_ui_->updateReleaseNotes->setAccessibleDescription(
        tr("Opens a browser to show the release notes for %1").arg(new_version_));
    header_ui_->updateDownload->setAccessibleName(tr("Download update %1").arg(new_version_));
    header_ui_->updateDownload->setAccessibleDescription(
        tr("Starts the download process for update %1").arg(new_version_));



    connect(header_ui_->updateReleaseNotes, &QPushButton::clicked, this, [this]() {
            QDesktopServices::openUrl(QUrl(release_notes_));
        });
}

void WelcomeHeaderWidget::setAvailableUpdateVersion(QString newVersion, QString releaseNotes)
{
    new_version_ = newVersion;

    QUrl url(releaseNotes, QUrl::StrictMode);
    if (!url.isValid()
        || url.scheme() != QStringLiteral("https")
        || (!url.host().endsWith(QStringLiteral(".wireshark.org"))
            && !url.host().endsWith(QStringLiteral(".stratoshark.org")))) {
        release_notes_ = QString(application_flavor_release_notes_url());
    } else {
        release_notes_ = releaseNotes;
    }

    updateSoftwareUpdateInfo();
}

void WelcomeHeaderWidget::clearAvailableUpdateVersion()
{
    new_version_.clear();
    release_notes_.clear();
    updateSoftwareUpdateInfo();
}

void WelcomeHeaderWidget::skipThisVersion()
{
    if (!new_version_.isEmpty() && !skipped_versions_.contains(new_version_)) {
        skipped_versions_.append(new_version_);
        clearAvailableUpdateVersion();
    }
}

bool WelcomeHeaderWidget::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
    {
        updateStyleSheet();
        break;
    }
    case QEvent::LanguageChange:
    {
        header_ui_->retranslateUi(this);
        break;
    }
    default:
        break;

    }
    return QWidget::event(event);
}

void WelcomeHeaderWidget::updateStyleSheet()
{
    setStyleSheet(ThemeManager::styleSheet(QStringLiteral("widgets/welcome-header")));
}
