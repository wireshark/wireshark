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

/**
 * @brief A dialog window displaying active conversations in a capture file.
 */
class ConversationDialog : public TrafficTableDialog
{
    Q_OBJECT

public:
    /**
     * @brief Create a new conversation window.
     *
     * @param parent Parent widget.
     * @param cf Capture file. No statistics will be calculated if this is NULL.
     */
    explicit ConversationDialog(QWidget &parent, CaptureFile &cf);

protected:
    /**
     * @brief Slot triggered when the underlying capture file is closing.
     */
    void captureFileClosing() override;

signals:
    /**
     * @brief Signal emitted to open the Follow Stream dialog.
     * @param proto_id The protocol identifier.
     * @param stream_num The primary stream number.
     * @param sub_stream_num The sub-stream number.
     */
    void openFollowStreamDialog(int proto_id, unsigned stream_num, unsigned sub_stream_num);

    /**
     * @brief Signal emitted to open the IO Graph dialog for selected conversations.
     * @param filtered True if the graph should apply current display filters.
     * @param conv_ids A vector of selected conversation IDs.
     * @param conv_agg A vector of aggregation values associated with the conversations.
     */
    void openIOGraph(bool filtered, QVector<uint> conv_ids, QVector<QVariant> conv_agg);

private:
    /** Pointer to the Follow Stream push button. */
    QPushButton *follow_bt_;

    /** Pointer to the TCP Stream Graph push button. */
    QPushButton *graph_bt_;

    /** Pointer to the IO Graph push button. */
    QPushButton *iograph_bt_;

    /** Flag indicating if a TCP stream graph has been requested. */
    bool tcp_graph_requested_;

private slots:
    /**
     * @brief Slot triggered to initiate following a stream based on the selected conversation.
     */
    void followStream();

    /**
     * @brief Slot triggered to plot a TCP graph for the selected conversation.
     */
    void graphTcp();

    /**
     * @brief Slot triggered to open the IO Graph dialog for the selected conversations.
     */
    void showGraphIO();

    /**
     * @brief Slot triggered when help is requested from the dialog's button box.
     */
    void on_buttonBox_helpRequested() override;

    /**
     * @brief Slot triggered to indicate whether a display filter was successfully applied.
     * @param success True if the display filter application succeeded, false otherwise.
     */
    void displayFilterSuccess(bool success);

    /**
     * @brief Slot triggered when the active protocol tab is changed.
     * @param idx The index of the newly active tab.
     */
    void tabChanged(int idx);
};

/**
 * @brief Initializes the conversation table with a filter.
 *
 * @param ct Pointer to the register_ct structure.
 * @param filter The filter string for conversations.
 */
void init_conversation_table(struct register_ct* ct, const char *filter);

#endif // CONVERSATION_DIALOG_H
