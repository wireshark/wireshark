/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TIME_SHIFT_DIALOG_H
#define TIME_SHIFT_DIALOG_H

#include <config.h>

#include <epan/cfile.h>

#include <ui/qt/widgets/syntax_line_edit.h>

#include <QDialog>
#include <QPushButton>

namespace Ui {
class TimeShiftDialog;
}

/**
 * @brief Dialog for shifting packet timestamps in the current capture file,
 *        supporting uniform shifts across all packets, single-anchor adjustments,
 *        and two-point linear interpolation, as well as a full timestamp reset.
 */
class TimeShiftDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the Time Shift dialog.
     * @param parent Optional parent widget.
     * @param cf     Capture file whose timestamps will be modified; may be @c NULL.
     */
    explicit TimeShiftDialog(QWidget *parent = 0, capture_file *cf = NULL);

    /**
     * @brief Destroys the dialog and releases UI resources.
     */
    ~TimeShiftDialog();

public slots:
    /**
     * @brief Updates the capture file pointer when the active file changes.
     * @param cf New capture file to operate on; may be @c NULL.
     */
    void setCaptureFile(capture_file *cf) { cap_file_ = cf; }

signals:
    /**
     * @brief Emitted after a time-shift operation has been successfully applied,
     *        so that other views can refresh their timestamp displays.
     */
    void timeShifted();

private:
    Ui::TimeShiftDialog *ts_ui_;       /**< Qt Designer-generated UI object. */
    capture_file        *cap_file_;    /**< Capture file whose timestamps are being modified. */
    QPushButton         *apply_button_;/**< Apply button; enabled only when inputs are valid. */
    QString              syntax_err_;  /**< Human-readable description of the current input error, if any. */

    /**
     * @brief Refreshes the enabled/disabled state of all input widgets and the
     *        Apply button based on the currently selected mode and input validity.
     */
    void enableWidgets();

    /**
     * @brief Validates a frame-number input field and updates its syntax state.
     * @param frame_le The SyntaxLineEdit containing the frame number to validate.
     */
    void checkFrameNumber(SyntaxLineEdit &frame_le);

    /**
     * @brief Validates a date/time input field and updates its syntax state.
     * @param time_le The SyntaxLineEdit containing the timestamp string to validate.
     */
    void checkDateTime(SyntaxLineEdit &time_le);

private slots:
    /**
     * @brief Switches to "shift all packets by a fixed offset" mode when toggled on.
     * @param checked @c true when this radio button becomes active.
     */
    void on_shiftAllButton_toggled(bool checked);

    /**
     * @brief Switches to "set one packet to an exact time" mode when toggled on.
     * @param checked @c true when this radio button becomes active.
     */
    void on_setOneButton_toggled(bool checked);

    /**
     * @brief Switches to "unshift all packets" (reset) mode when toggled on.
     * @param checked @c true when this radio button becomes active.
     */
    void on_unshiftAllButton_toggled(bool checked);

    /**
     * @brief Enables or disables the second anchor point for two-point interpolation.
     * @param checked @c true to enable the second anchor; @c false to disable it.
     */
    void on_setTwoCheckBox_toggled(bool checked);

    /**
     * @brief Validates the shift-all time offset as the user types.
     * @param sa_text Current text of the shift-all time line edit.
     */
    void on_shiftAllTimeLineEdit_textChanged(const QString &sa_text);

    /**
     * @brief Validates the set-one target timestamp as the user types.
     * @param so_text Current text of the set-one time line edit.
     */
    void on_setOneTimeLineEdit_textChanged(const QString &so_text);

    /**
     * @brief Validates the set-one anchor frame number as the user types.
     * @param frame_text Current text of the set-one frame number line edit.
     */
    void on_setOneFrameLineEdit_textChanged(const QString &frame_text);

    /**
     * @brief Validates the set-two anchor frame number as the user types.
     * @param frame_text Current text of the set-two frame number line edit.
     */
    void on_setTwoFrameLineEdit_textChanged(const QString &frame_text);

    /**
     * @brief Validates the set-two target timestamp as the user types.
     * @param st_text Current text of the set-two time line edit.
     */
    void on_setTwoTimeLineEdit_textChanged(const QString &st_text);

    /**
     * @brief Applies the configured time-shift operation to the capture file
     *        and emits timeShifted() on success.
     */
    void applyTimeShift();

    /**
     * @brief Opens the context-sensitive help page for the Time Shift dialog.
     */
    void on_buttonBox_helpRequested();
};

#endif // TIME_SHIFT_DIALOG_H
