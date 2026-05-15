/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_COMMENT_DIALOG_H
#define PACKET_COMMENT_DIALOG_H

#include "geometry_state_dialog.h"

namespace Ui {
class PacketCommentDialog;
}

/**
 * @brief Dialog for viewing or editing a packet comment.
 */
class PacketCommentDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new PacketCommentDialog object.
     * @param isEdit True if the dialog is used to edit an existing comment, false otherwise.
     * @param parent The parent widget.
     * @param comment The initial comment text.
     */
    explicit PacketCommentDialog(bool isEdit, QWidget *parent = 0, QString comment = QString());

    /**
     * @brief Destroys the PacketCommentDialog object.
     */
    ~PacketCommentDialog();

    /**
     * @brief Retrieves the text of the packet comment.
     * @return A QString containing the current packet comment text.
     */
    QString text();

private slots:
    /**
     * @brief Handles the event when the help button is clicked in the dialog's button box.
     */
    void on_buttonBox_helpRequested();

private:
    /** @brief Pointer to the user interface object for this dialog. */
    Ui::PacketCommentDialog *pc_ui_;
};

#endif // PACKET_COMMENT_DIALOG_H
