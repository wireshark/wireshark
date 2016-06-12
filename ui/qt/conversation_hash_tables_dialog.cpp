/* conversation_hash_tables_dialog.cpp
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

#include "conversation_hash_tables_dialog.h"
#include <ui_conversation_hash_tables_dialog.h>

#include "config.h"

#include <glib.h>

#include <epan/conversation.h>
#include <epan/conversation_debug.h>

#include "qt_ui_utils.h"
#include "wireshark_application.h"

ConversationHashTablesDialog::ConversationHashTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::ConversationHashTablesDialog)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);

    setWindowTitle(wsApp->windowTitleString(tr("Dissector Tables")));

    QString html;

    html += "<h3>Conversation Hash Tables</h3>\n";

    html += hashTableToHtmlTable("conversation_hashtable_exact", get_conversation_hashtable_exact());
    html += hashTableToHtmlTable("conversation_hashtable_no_addr2", get_conversation_hashtable_no_addr2());
    html += hashTableToHtmlTable("conversation_hashtable_no_port2", get_conversation_hashtable_no_port2());
    html += hashTableToHtmlTable("conversation_hashtable_no_addr2_or_port2", get_conversation_hashtable_no_addr2_or_port2());

    ui->conversationTextEdit->setHtml(html);
}

ConversationHashTablesDialog::~ConversationHashTablesDialog()
{
    delete ui;
}

const QString ConversationHashTablesDialog::hashTableToHtmlTable(const QString table_name, struct _GHashTable *hash_table)
{
    GList *conversation_keys = NULL;
    if (hash_table) conversation_keys = g_hash_table_get_keys(hash_table);
    int num_keys = g_list_length(conversation_keys);

    QString html_table = QString("<p>%1, %2 entries</p>").arg(table_name).arg(num_keys);
    if (num_keys < 1) return html_table;

    int one_em = fontMetrics().height();
    html_table += QString("<table cellpadding=\"%1\">\n").arg(one_em / 4);

    html_table += "<tr><th align=\"left\">Address 1</th><th align=\"left\">Port 1</th><th align=\"left\">Address 2</th><th align=\"left\">Port 2</th></tr>\n";

    // XXX Add a column for the hash value.
    for (GList *ck_entry = conversation_keys; ck_entry; ck_entry = g_list_next(ck_entry)) {
        const conversation_key *conv_key = (conversation_key *) ck_entry->data;
        html_table += QString("<tr><td>%1</td><td>%2</td><td>%3</td><td>%4</td></tr>\n")
                .arg(address_to_qstring(&conv_key->addr1))
                .arg(conv_key->port1)
                .arg(address_to_qstring(&conv_key->addr2))
                .arg(conv_key->port2);
    }
    html_table += "</table>\n";
    return html_table;
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
