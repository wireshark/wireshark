/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_HEADER_WIDGET_H
#define WELCOME_HEADER_WIDGET_H

#include <QWidget>

class QPropertyAnimation;

namespace Ui {
class WelcomeHeaderWidget;
}

/**
 * @brief A widget displaying the header section of the welcome screen.
 */
class WelcomeHeaderWidget : public QWidget {
    Q_OBJECT
public:
    /**
     * @brief Constructs a new WelcomeHeaderWidget.
     * @param parent The parent widget.
     */
    explicit WelcomeHeaderWidget(QWidget *parent = nullptr);

    /**
     * @brief Destroys the WelcomeHeaderWidget.
     */
    ~WelcomeHeaderWidget();

    /**
     * @brief Updates the stylesheets for the header widget and its children.
     */
    void updateStyleSheets();

protected:
    /**
     * @brief Handles generic events for the widget.
     * @param event The event to process.
     * @return True if the event was handled, false otherwise.
     */
    virtual bool event(QEvent *event) override;

private:
    /** @brief Pointer to the UI object for this widget. */
    Ui::WelcomeHeaderWidget *header_ui_;

    /** @brief Animation object for pulsing visual effects. */
    QPropertyAnimation *pulseAnimation_;

    /** @brief String containing the newly available software version. */
    QString new_version_;

    /** @brief String containing the release notes for the new version. */
    QString release_notes_;

    /** @brief List of versions that the user has chosen to skip. */
    QStringList skipped_versions_;

    /**
     * @brief Refreshes the display based on available software update information.
     */
    void updateSoftwareUpdateInfo();

    /**
     * @brief Updates the internal stylesheet for the widget.
     */
    void updateStyleSheet();

    /**
     * @brief Records the current new version as skipped and hides the update notification.
     */
    void skipThisVersion();

private slots:
    /**
     * @brief Slot to handle notification of a newly available software version.
     * @param newVersion The version string of the new release.
     * @param releaseNotes The URL or text of the release notes.
     */
    void setAvailableUpdateVersion(QString newVersion, QString releaseNotes);

    /**
     * @brief Slot to clear the currently displayed software update notification.
     */
    void clearAvailableUpdateVersion();

};

#endif // WELCOME_HEADER_WIDGET_H
