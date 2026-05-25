/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PROGRESS_FRAME_H
#define PROGRESS_FRAME_H

#include <QFrame>

namespace Ui {
class ProgressFrame;
}

class ProgressFrame;
class QDialogButtonBox;
class QElapsedTimer;
class QGraphicsOpacityEffect;
class QPropertyAnimation;

/**
 * @brief Define the structure describing a progress dialog.
 */
struct progdlg {
    /** @brief This progress frame. */
    ProgressFrame *progress_frame;

    /** @brief Progress frame's main window. */
    QWidget *top_level_window;
};

/**
 * @brief A frame for displaying progress indications and dialogs.
 */
class ProgressFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ProgressFrame object.
     * @param parent The parent widget.
     */
    explicit ProgressFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the ProgressFrame object.
     */
    ~ProgressFrame();

#ifdef QWINTASKBARPROGRESS_H
    /**
     * @brief Enables or disables taskbar progress updates.
     * @param enable True to enable taskbar updates, false to disable.
     */
    void enableTaskbarUpdates(bool enable = true) { update_taskbar_ = enable; }
#endif

    /**
     * @brief Adds the progress frame to a dialog button box.
     * @param button_box Pointer to the dialog button box.
     * @param main_window Pointer to the main window object.
     */
    static void addToButtonBox(QDialogButtonBox *button_box, QObject *main_window);

    /**
     * @brief Handles the event when the capture file is closing.
     */
    void captureFileClosing();

public slots:
    /**
     * @brief Shows a progress indicator with a title.
     * @param title The title of the progress dialog.
     * @param animate True to animate the progress indicator.
     * @param terminate_is_stop True if terminating acts as a stop action.
     * @param stop_flag Pointer to a boolean flag used to indicate a stop request.
     * @param value The initial progress value.
     * @return A pointer to the progdlg structure.
     */
    struct progdlg *showProgress(const QString &title, bool animate, bool terminate_is_stop, bool *stop_flag, int value = 0);

    /**
     * @brief Shows a busy/indeterminate progress indicator.
     * @param animate True to animate the progress indicator.
     * @param terminate_is_stop True if terminating acts as a stop action.
     * @param stop_flag Pointer to a boolean flag used to indicate a stop request.
     * @return A pointer to the progdlg structure.
     */
    struct progdlg *showBusy(bool animate, bool terminate_is_stop, bool *stop_flag);

    /**
     * @brief Sets the current progress value.
     * @param value The new progress value.
     */
    void setValue(int value);

    /** @brief Sets the current progress title. */
    void setTitle(const QString &title);

    /** @brief Sets the current progress status. */
    void setStatus(const QString &status);

    /**
     * @brief Hides the progress frame.
     */
    void hide();

signals:
    /**
     * @brief Signal emitted to request showing the progress frame.
     * @param animate True to animate the progress indicator.
     * @param terminate_is_stop True if terminating acts as a stop action.
     * @param stop_flag Pointer to the stop flag.
     */
    void showRequested(bool animate, bool terminate_is_stop, bool *stop_flag);

    /**
     * @brief Signal emitted when the progress value changes.
     * @param value The new progress value.
     */
    void valueChanged(int value);

    /**
     * @brief Signal emitted when the maximum progress value changes.
     * @param value The new maximum value.
     */
    void maximumValueChanged(int value);

    /**
     * @brief Signal emitted to hide the progress frame.
     */
    void setHidden();

    /**
     * @brief Signal emitted to request stopping the current loading operation.
     */
    void stopLoading();

protected:
    /**
     * @brief Handles timer events.
     * @param event Pointer to the timer event.
     */
    void timerEvent(QTimerEvent *event) override;

private:
    /** @brief Update the label for progress dialog. */
    void updateLabel();

    /** @brief Elide text if larger than some maximum value */
    QString elideLabel(const QString &title) const;

    /** @brief Pointer to the user interface object for this frame. */
    Ui::ProgressFrame *ui;

    /** @brief The internal progress dialog structure. */
    struct progdlg progress_dialog_;

    /** @brief The current progress message. */
    QString message_;

    /** @brief The current status text. */
    QString status_;

    /** @brief Flag indicating if termination is a stop action. */
    bool terminate_is_stop_;

    /** @brief Pointer to the external stop flag. */
    bool *stop_flag_;

    /** @brief Timer ID for showing the frame. */
    int show_timer_;

    /** @brief Opacity effect for animations. */
    QGraphicsOpacityEffect *effect_;

    /** @brief Property animation for fade effects. */
    QPropertyAnimation *animation_;

#ifdef QWINTASKBARPROGRESS_H
    /** @brief Flag indicating if taskbar updates are enabled. */
    bool update_taskbar_;

    /** @brief Pointer to the Windows taskbar progress object. */
    QWinTaskbarProgress *taskbar_progress_;
#endif

private slots:
    /**
     * @brief Handles the event when the stop button is clicked.
     */
    void on_stopButton_clicked();

    /**
     * @brief Internal slot to show the progress frame.
     * @param animate True to animate the frame.
     * @param terminate_is_stop True if terminating acts as a stop action.
     * @param stop_flag Pointer to the stop flag.
     */
    void show(bool animate, bool terminate_is_stop, bool *stop_flag);

    /**
     * @brief Internal slot to set the maximum progress value.
     * @param value The new maximum value.
     */
    void setMaximumValue(int value);
};

#endif // PROGRESS_FRAME_H
