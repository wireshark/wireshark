/* conversation_hash_tables_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "conversation_hash_tables_dialog.h"
#include <ui_conversation_hash_tables_dialog.h>

#include "config.h"

#include <glib.h>

#include <epan/conversation.h>
#include <epan/conversation_debug.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include "wireshark_application.h"

ConversationHashTablesDialog::ConversationHashTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::ConversationHashTablesDialog)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);
    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowTitle(wsApp->windowTitleString(tr("Conversation Hash Tables")));

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

static void
populate_html_table(gpointer data, gpointer user_data)
{
    const conversation_key_t conv_key = (conversation_key_t)data;
    QString* html_table = (QString*)user_data;
    gchar* tmp = conversation_get_html_hash(conv_key);

    // XXX Add a column for the hash value.
    (*html_table) += QString(tmp);
    wmem_free(NULL, tmp);
}

const QString ConversationHashTablesDialog::hashTableToHtmlTable(const QString table_name, wmem_map_t *hash_table)
{
    wmem_list_t *conversation_keys = NULL;
    guint num_keys = 0;
    if (hash_table)
    {
        conversation_keys = wmem_map_get_keys(NULL, hash_table);
        num_keys = wmem_list_count(conversation_keys);
    }

    QString html_table = QString("<p>%1, %2 entries</p>").arg(table_name).arg(num_keys);
    if (num_keys > 0)
    {
        int one_em = fontMetrics().height();
        html_table += QString("<table cellpadding=\"%1\">\n").arg(one_em / 4);

        html_table += "<tr><th align=\"left\">Address 1</th><th align=\"left\">Port 1</th><th align=\"left\">Address 2</th><th align=\"left\">Port 2</th></tr>\n";

        wmem_list_foreach(conversation_keys, populate_html_table, (void*)&html_table);
        html_table += "</table>\n";
    }
    if (conversation_keys)
        wmem_destroy_list(conversation_keys);
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
