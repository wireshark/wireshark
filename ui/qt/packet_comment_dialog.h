/* packet_comment_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_COMMENT_DIALOG_H
#define PACKET_COMMENT_DIALOG_H

#include <glib.h>

#include "geometry_state_dialog.h"

namespace Ui {
class PacketCommentDialog;
}

class PacketCommentDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit PacketCommentDialog(guint32 frame, QWidget *parent = 0, QString comment = QString());
    ~PacketCommentDialog();
    QString text();

private slots:
    void on_buttonBox_helpRequested();

private:
    Ui::PacketCommentDialog *pc_ui_;
};

#endif // PACKET_COMMENT_DIALOG_H
