/* packet_comment_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "packet_comment_dialog.h"
#include <ui_packet_comment_dialog.h>

#include "wireshark_application.h"

PacketCommentDialog::PacketCommentDialog(QWidget *parent, QString comment) :
    GeometryStateDialog(parent),
    pc_ui_(new Ui::PacketCommentDialog)
{
    pc_ui_->setupUi(this);
    loadGeometry();
    setWindowTitle(wsApp->windowTitleString(tr("Packet Comment")));

    pc_ui_->commentTextEdit->setPlainText(comment);
}

PacketCommentDialog::~PacketCommentDialog()
{
    delete pc_ui_;
}

QString PacketCommentDialog::text()
{
    return pc_ui_->commentTextEdit->toPlainText();
}

void PacketCommentDialog::on_buttonBox_helpRequested()
{
//    wsApp->helpTopicAction(HELP_PACKET_COMMENT_DIALOG);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */

