/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_COMMENT_DIALOG_H
#define CAPTURE_COMMENT_DIALOG_H

#include "wireshark_dialog.h"

namespace Ui {
class CaptureCommentDialog;
}

/**
 * @brief A dialog window for viewing and editing capture file comments.
 */
class CaptureCommentDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CaptureCommentDialog.
     * @param parent The parent widget.
     * @param capture_file The capture file associated with the comments.
     */
    explicit CaptureCommentDialog(QWidget &parent, CaptureFile &capture_file);

    /**
     * @brief Destroys the CaptureCommentDialog.
     */
    ~CaptureCommentDialog();

signals:
    /**
     * @brief Signal emitted when a capture comment has been modified.
     */
    void captureCommentChanged();

private slots:
    /**
     * @brief Slot triggered to add a new comment.
     */
    void addComment();

    /**
     * @brief Slot triggered to update the state of the dialog's widgets.
     */
    void updateWidgets();

    /**
     * @brief Slot triggered when the help button is requested from the button box.
     */
    void on_buttonBox_helpRequested();

    /**
     * @brief Slot triggered when the dialog is accepted (e.g., OK is clicked).
     */
    void on_buttonBox_accepted();

    /**
     * @brief Slot triggered when the dialog is rejected (e.g., Cancel is clicked).
     */
    void on_buttonBox_rejected();

private:
    /** Pointer to the add action button. */
    QPushButton *actionAddButton;

    /** Pointer to the generated UI elements. */
    Ui::CaptureCommentDialog *ui;
};

#endif // CAPTURE_COMMENT_DIALOG_H
