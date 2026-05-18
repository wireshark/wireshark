/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WELCOME_PAGE_H
#define WELCOME_PAGE_H

#include <QFrame>

class QListWidget;
class QListWidgetItem;
class QMenu;
class CaptureCardWidget;
class InterfaceFrame;

#include <ui/qt/widgets/splash_overlay.h>

namespace Ui {
    class WelcomePage;
}

/**
 * @brief Widget displayed on application startup, providing interface selection, capture filter configuration, and recent file access.
 */
class WelcomePage : public QFrame
{
    Q_OBJECT
public:
    /**
     * @brief Constructs the WelcomePage widget.
     * @param parent Optional parent widget.
     */
    explicit WelcomePage(QWidget *parent = 0);

    /**
     * @brief Destroys the WelcomePage widget.
     */
    virtual ~WelcomePage();

    /**
     * @brief Returns the interface frame embedded in this page.
     * @return Pointer to the InterfaceFrame.
     */
    InterfaceFrame *getInterfaceFrame();

    /**
     * @brief Returns the capture card widget.
     * @return Pointer to the CaptureCardWidget.
     */
    CaptureCardWidget *captureCard();

    /**
     * @brief Returns the current capture filter string.
     * @return The capture filter expression.
     */
    const QString captureFilter();

    /**
     * @brief Sets the capture filter expression.
     * @param capture_filter The filter string to apply.
     */
    void setCaptureFilter(const QString capture_filter);

    /**
     * @brief Refreshes style sheets for all child widgets.
     */
    void updateStyleSheets();

public slots:
    /**
     * @brief Handles selection of a capture interface by the user.
     */
    void interfaceSelected();

    /**
     * @brief Updates the capture filter input field with the given text.
     * @param capture_filter The filter string to display.
     */
    void setCaptureFilterText(const QString capture_filter);

protected:
    /**
     * @brief Handles generic Qt events for this widget.
     * @param event The event to process.
     * @return True if the event was handled; otherwise false.
     */
    virtual bool event(QEvent *event);

    /**
     * @brief Handles widget resize events.
     * @param event The resize event containing the new size.
     */
    virtual void resizeEvent(QResizeEvent *event);

    /**
     * @brief Handles widget show events, triggering any necessary initialization.
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event);

protected slots:
    /**
     * @brief Slot invoked when the "Open File" section label is clicked.
     */
    void on_openFileSectionLabel_clicked();

private:
    /** @brief Pointer to the Qt Designer-generated UI object. */
    Ui::WelcomePage *welcome_ui_;

    /** @brief String used to populate the "show in" display field. */
    QString show_in_str_;

    /** @brief Overlay widget shown during application initialization. */
    SplashOverlay *splash_overlay_;

    /**
     * @brief Recalculates and applies the sidebar layout based on current geometry.
     */
    void updateSidebarLayout();

signals:
    /**
     * @brief Emitted when the user activates a recent capture file.
     * @param cfile Absolute path to the activated file.
     */
    void recentFileActivated(QString cfile);

private slots:
    /**
     * @brief Slot called once the application has finished initializing.
     */
    void appInitialized();

    /**
     * @brief Shows a context menu for the recent capture files list.
     * @param pos The position at which to display the context menu.
     */
    void showCaptureFilesContextMenu(QPoint pos);

    /**
     * @brief Reloads and applies sidebar layout preferences from application settings.
     */
    void applySidebarPreferences();
};

#endif // WELCOME_PAGE_H
