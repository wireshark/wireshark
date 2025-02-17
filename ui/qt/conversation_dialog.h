/** @file
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

class ConversationDialog : public TrafficTableDialog
{
    Q_OBJECT

public:
    /** Create a new conversation window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     */
    explicit ConversationDialog(QWidget &parent, CaptureFile &cf);

protected:
    void captureFileClosing();

signals:
    void openFollowStreamDialog(int proto_id, unsigned stream_num, unsigned sub_stream_num);
    void openIOGraph(bool filtered, QVector<uint> conv_ids, QVector<QVariant> conv_agg);

private:
    QPushButton *follow_bt_;
    QPushButton *graph_bt_;
    QPushButton *iograph_bt_;

    bool tcp_graph_requested_;

private slots:
    void followStream();
    void graphTcp();
    void showGraphIO();
    void on_buttonBox_helpRequested();
    void displayFilterSuccess(bool success);
    void tabChanged(int idx);
};

void init_conversation_table(struct register_ct* ct, const char *filter);

#endif // CONVERSATION_DIALOG_H
