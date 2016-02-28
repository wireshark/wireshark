/* conversation_hash_tables_dialog.h
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

#ifndef CONVERSATION_HASH_TABLES_DIALOG_H
#define CONVERSATION_HASH_TABLES_DIALOG_H

#include "geometry_state_dialog.h"

namespace Ui {
class ConversationHashTablesDialog;
}

class ConversationHashTablesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ConversationHashTablesDialog(QWidget *parent = 0);
    ~ConversationHashTablesDialog();

private:
    Ui::ConversationHashTablesDialog *ui;

    const QString hashTableToHtmlTable(const QString table_name, struct _GHashTable *hash_table);
};

#endif // CONVERSATION_HASH_TABLES_DIALOG_H

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
