/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAIN_STATUS_BAR_H
#define MAIN_STATUS_BAR_H

#include "config.h"

#include <epan/cfile.h>

#include "capture/capture_session.h"

#include <ui/qt/utils/field_information.h>
#include <ui/qt/widgets/label_stack.h>
#include <ui/qt/widgets/clickable_label.h>
#include "progress_frame.h"
#include "wireshark_application.h"

#include <QLabel>
#include <QMenu>
#include <QStatusBar>

class CaptureFile;
class QToolButton;

/**
 * @brief The main status bar of the application.
 */
class MainStatusBar : public QStatusBar
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new MainStatusBar.
     * @param parent The parent widget, defaults to 0.
     */
    explicit MainStatusBar(QWidget *parent = 0);

    /**
     * @brief Destroys the MainStatusBar.
     */
    virtual ~MainStatusBar();

    /**
     * @brief Shows the expert information dialog.
     */
    void showExpert();

    /**
     * @brief Handles the capture file closing event.
     */
    void captureFileClosing();

    /**
     * @brief Updates the expert information status.
     */
    void expertUpdate();

    /**
     * @brief Sets the file name to display.
     * @param cf The capture file.
     */
    void setFileName(CaptureFile &cf);

protected:

    /**
     * @brief Context identifiers for status bar messages.
     */
    enum StatusContext {
        /** @brief Main context. */
        STATUS_CTX_MAIN,
        /** @brief File context. */
        STATUS_CTX_FILE,
        /** @brief Field context. */
        STATUS_CTX_FIELD,
        /** @brief Byte context. */
        STATUS_CTX_BYTE,
        /** @brief Filter context. */
        STATUS_CTX_FILTER,
        /** @brief Progress context. */
        STATUS_CTX_PROGRESS,
        /** @brief Temporary context. */
        STATUS_CTX_TEMPORARY
    };

    /**
     * @brief Handles state change events.
     * @param event The event to handle.
     */
    virtual void changeEvent(QEvent* event);

    /**
     * @brief Displays the capture statistics.
     */
    virtual void showCaptureStatistics();

protected:
    /** Pointer to the active capture file. */
    capture_file* cap_file_;

    // Capture statistics
    /** Flag indicating if capture statistics are fixed. */
    bool cs_fixed_;

    /** Count of captured statistics. */
    uint64_t cs_count_;

    /**
     * @brief Pushes a generic status message.
     * @param status The status context.
     * @param message The message text.
     * @param messagetip Optional tooltip for the message.
     */
    void pushGenericStatus(StatusContext status, const QString& message, const QString& messagetip = QString());

    /**
     * @brief Pops a generic status message.
     * @param status The status context to pop.
     */
    void popGenericStatus(StatusContext status);

private:
    /** Button to trigger the expert info dialog. */
    QToolButton *expert_button_;

    /** Button to trigger capture comments. */
    QToolButton *comment_button_;

    /** Stack of info status labels. */
    LabelStack info_status_;

    /** Frame indicating current progress. */
    ProgressFrame progress_frame_;

    /** Stack of packet status labels. */
    LabelStack packet_status_;

    /** Label for the current profile status. */
    ClickableLabel profile_status_;

    /** String representing the ready message. */
    QString ready_msg_;

    /**
     * @brief Configures the status bar for a capture file.
     */
    void setStatusbarForCaptureFile();

signals:
    /**
     * @brief Signal emitted to show the expert info dialog.
     */
    void showExpertInfo();

    /**
     * @brief Signal emitted to edit the capture comment.
     */
    void editCaptureComment();

    /**
     * @brief Signal emitted to stop the loading process.
     */
    void stopLoading();

public slots:
    /**
     * @brief Sets the active capture file.
     * @param cf Pointer to the capture file.
     */
    void setCaptureFile(capture_file *cf);

    /**
     * @brief Handles a change in the selected field.
     * @param finfo Pointer to the new field information.
     */
    void selectedFieldChanged(FieldInformation * finfo);

    /**
     * @brief Handles a change in the highlighted field.
     * @param finfo Pointer to the highlighted field information.
     */
    void highlightedFieldChanged(FieldInformation * finfo);

    /**
     * @brief Handles a change in the selected frame.
     */
    void selectedFrameChanged(QList<int>);

    /**
     * @brief Updates the capture statistics.
     * @param cap_session Pointer to the capture session.
     */
    void updateCaptureStatistics(capture_session * cap_session);

    /**
     * @brief Updates fixed capture statistics.
     * @param cap_session Pointer to the capture session.
     */
    void updateCaptureFixedStatistics(capture_session * cap_session);

    /**
     * @brief Handles a capture event.
     * @param ev The capture event to process.
     */
    void captureEventHandler(CaptureEvent ev);

private slots:
    /**
     * @brief Slot triggered when the application is initialized.
     */
    void appInitialized();

    /**
     * @brief Toggles the background state.
     * @param enabled True if enabled, false otherwise.
     */
    void toggleBackground(bool enabled);

    /**
     * @brief Sets the active profile name.
     */
    void setProfileName();

    /**
     * @brief Switches to a different profile.
     */
    void switchToProfile();

    /**
     * @brief Opens the profile management interface.
     */
    void manageProfile();

    /**
     * @brief Shows the profile menu at a specific position.
     * @param global_pos The global coordinate position for the menu.
     * @param button The mouse button that triggered the event.
     */
    void showProfileMenu(const QPoint &global_pos, Qt::MouseButton button);

    /** Allows MainApplication to access private members. */
    friend MainApplication;
};

#endif // MAIN_STATUS_BAR_H
