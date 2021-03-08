/* conversation_hash_tables_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CONVERSATION_HASH_TABLES_DIALOG_H
#define CONVERSATION_HASH_TABLES_DIALOG_H

#include "geometry_state_dialog.h"
#include <epan/wmem/wmem.h>

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

    const QString hashTableToHtmlTable(const QString table_name, wmem_map_t *hash_table);
};

#endif // CONVERSATION_HASH_TABLES_DIALOG_H
