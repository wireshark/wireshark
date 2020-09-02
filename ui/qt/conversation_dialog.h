/* conversation_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CONVERSATION_DIALOG_H
#define CONVERSATION_DIALOG_H

#include "traffic_table_dialog.h"

class ConversationTreeWidget : public TrafficTableTreeWidget
{
    Q_OBJECT
public:
    explicit ConversationTreeWidget(QWidget *parent, register_ct_t* table);
    ~ConversationTreeWidget();

    static void tapReset(void *conv_hash_ptr);
    static void tapDraw(void *conv_hash_ptr);
    double minRelStartTime() { return min_rel_start_time_; }
    double maxRelStopTime() { return max_rel_stop_time_; }

public slots:
    void updateStartTime(bool absolute);

private:
    void initDirectionMap();
    void updateItems();
    double min_rel_start_time_; // seconds
    double max_rel_stop_time_; // seconds

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
    void openFollowStreamDialog(follow_type_t type, guint stream_num, guint sub_stream_num);
    void openTcpStreamGraph(int graph_type);

private:
    QPushButton *follow_bt_;
    QPushButton *graph_bt_;

    bool addTrafficTable(register_ct_t* table);
    conv_item_t *currentConversation();

    bool tcp_graph_requested_;

private slots:
    void currentTabChanged();
    void conversationSelectionChanged();
    void on_displayFilterCheckBox_toggled(bool checked);
    void followStream();
    void graphTcp();
    void on_buttonBox_helpRequested();
    void displayFilterSuccess(bool success);
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
