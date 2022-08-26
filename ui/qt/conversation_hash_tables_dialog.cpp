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
#include "main_application.h"

static void
fill_named_table(gpointer key, gpointer value _U_, gpointer user_data)
{
    const conversation_element_t *elements = static_cast<const conversation_element_t *>(key);
    QString* html_table = static_cast<QString *>(user_data);

    if (!elements || !html_table) {
        return;
    }

    if (html_table->isEmpty()) {
        html_table->append("<tr>");
        int addr_count = 1;
        int port_count = 1;
        int string_count = 1;
        int uint_count = 1;
        int uint64_count = 1;
        for (const conversation_element_t *cur_el = elements; ; cur_el++) {
            QString title;
            switch (cur_el->type) {
            case CE_ADDRESS:
                title = QString("Address %1").arg(addr_count++);
                break;
            case CE_PORT:
                title = QString("Port %1").arg(port_count++);
                break;
            case CE_STRING:
                title = QString("String %1").arg(string_count++);
                break;
            case CE_UINT:
                title = QString("UInt %1").arg(uint_count++);
                break;
            case CE_UINT64:
                title = QString("UInt64 %1").arg(uint64_count++);
                break;
            case CE_CONVERSATION_TYPE:
                html_table->append(QString("<th>Endpoint</th>"));
                goto title_done;
                break;
            }
            html_table->append(QString("<th>%1</th>").arg(title));
        }
        html_table->append("</tr>\n");
    }
title_done:

    html_table->append("<tr>");

    for (const conversation_element_t *cur_el = elements; ; cur_el++) {
        QString val;
        switch (cur_el->type) {
        case CE_ADDRESS:
            val = address_to_qstring(&cur_el->addr_val);
            break;
        case CE_PORT:
            val = QString::number(cur_el->port_val);
            break;
        case CE_STRING:
            val = cur_el->str_val;
            break;
        case CE_UINT:
            val = QString::number(cur_el->uint_val);
            break;
        case CE_UINT64:
            val = QString::number(cur_el->uint64_val);
            break;
        case CE_CONVERSATION_TYPE:
            html_table->append(QString("<td>%1</td>").arg(QString::number(cur_el->conversation_type_val)));
            goto val_done;
            break;
        }
        html_table->append(QString("<td>%1</td>").arg(val));
    }
val_done:

    html_table->append("</tr>\n");
}

ConversationHashTablesDialog::ConversationHashTablesDialog(QWidget *parent) :
    GeometryStateDialog(parent),
    ui(new Ui::ConversationHashTablesDialog)
{
    ui->setupUi(this);
    if (parent) loadGeometry(parent->width() * 3 / 4, parent->height() * 3 / 4);
    setAttribute(Qt::WA_DeleteOnClose, true);
    setWindowTitle(mainApp->windowTitleString(tr("Conversation Hash Tables")));

    QString html;

    html += "<h2>Conversation Hash Tables</h2>\n";

    wmem_map_t *conversation_tables = get_conversation_hashtables();
    wmem_list_t *table_names = wmem_map_get_keys(NULL, conversation_tables);
    for (wmem_list_frame_t *cur_frame = wmem_list_head(table_names); cur_frame; cur_frame = wmem_list_frame_next(cur_frame))
    {
        const char *table_name = static_cast<const char *>(wmem_list_frame_data(cur_frame));
        wmem_map_t *table = static_cast<wmem_map_t *>(wmem_map_lookup(conversation_tables, table_name));

        if (!table) {
            html += QString("<h3>%1, Error: table not found</h3>\n").arg(table_name);
            continue;
        }

        html += QString("<h3>%1, %2 entries</h3>\n").arg(table_name).arg(wmem_map_size(table));
        QString html_table;
        html += "<table>\n";
        wmem_map_foreach(table, fill_named_table, &html_table);
        html += html_table;
        html += "</table>\n";
    }
    wmem_destroy_list(table_names);
    ui->conversationTextEdit->setHtml(html);
}

ConversationHashTablesDialog::~ConversationHashTablesDialog()
{
    delete ui;
}
