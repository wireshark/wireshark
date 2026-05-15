/** @file
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
#include <epan/wmem_scopes.h>

namespace Ui {
class ConversationHashTablesDialog;
}

/**
 * @brief A dialog for displaying the contents and statistics of conversation hash tables.
 */
class ConversationHashTablesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ConversationHashTablesDialog.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ConversationHashTablesDialog(QWidget *parent = 0);

    /**
     * @brief Destroys the ConversationHashTablesDialog.
     */
    ~ConversationHashTablesDialog();

private:
    /** Pointer to the generated UI elements. */
    Ui::ConversationHashTablesDialog *ui;

    /**
     * @brief Converts a given core hash table into an HTML-formatted table string.
     * @param table_name The name or title to assign to the HTML table.
     * @param hash_table Pointer to the core wmem map representing the hash table.
     * @return The HTML-formatted string representation of the hash table.
     */
    const QString hashTableToHtmlTable(const QString table_name, wmem_map_t *hash_table);
};

#endif // CONVERSATION_HASH_TABLES_DIALOG_H
