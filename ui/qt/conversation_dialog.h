/* conversation_dialog.h
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

#ifndef CONVERSATION_DIALOG_H
#define CONVERSATION_DIALOG_H

#include "traffic_table_dialog.h"

Q_DECLARE_METATYPE(conv_item_t *)

class ConversationTreeWidget : public TrafficTableTreeWidget
{
    Q_OBJECT
public:
    explicit ConversationTreeWidget(QWidget *parent, register_ct_t* table);
    ~ConversationTreeWidget();

    static void tapReset(void *conv_hash_ptr);
    static void tapDraw(void *conv_hash_ptr);

public slots:
    void updateStartTime(bool absolute);

private:
    void initDirectionMap();
    void updateItems();

private slots:
    void filterActionTriggered();
};

class ConversationDialog : public TrafficTableDialog
{
    Q_OBJECT

public:
    /** Create a new conversation window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     * @param cli_proto_id If valid, add this protocol and bring it to the front.
     * @param filter Display filter to apply.
     */
    explicit ConversationDialog(QWidget &parent, CaptureFile &cf, int cli_proto_id = -1, const char *filter = NULL);
    ~ConversationDialog();

public slots:
    void captureFileClosing();

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);
    void openFollowStreamDialog(follow_type_t type);
    void openTcpStreamGraph(int graph_type);

private:
    QPushButton *follow_bt_;
    QPushButton *graph_bt_;

    bool addTrafficTable(register_ct_t* table);
    conv_item_t *currentConversation();

private slots:
    void currentTabChanged();
    void conversationSelectionChanged();
    void on_displayFilterCheckBox_toggled(bool checked);
    void followStream();
    void graphTcp();
    void on_buttonBox_helpRequested();
};

void init_conversation_table(struct register_ct* ct, const char *filter);

#endif // CONVERSATION_DIALOG_H

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
