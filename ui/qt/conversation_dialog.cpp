/* conversation_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "conversation_dialog.h"

#include <epan/prefs.h>
#include <epan/to_str.h>
#include <epan/dissectors/packet-tcp.h>

#include "ui/recent.h"
#include "ui/tap-tcp-stream.h"

#include "wsutil/str_util.h"

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/models/timeline_delegate.h>
#include <ui/qt/models/atap_data_model.h>
#include <ui/qt/widgets/traffic_tab.h>
#include <ui/qt/widgets/traffic_types_list.h>
#include "main_application.h"

#include <QCheckBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QPushButton>
#include <QString>

// To do:
// - https://gitlab.com/wireshark/wireshark/-/issues/6727
//   - Wide last column?
//   + No arrows on unsorted columns
//   - Add follow stream to context menu
//   + Change "A <- B" to "B -> A"
// - Improper wildcard handling https://gitlab.com/wireshark/wireshark/-/issues/8010
// - TShark consolidation https://gitlab.com/wireshark/wireshark/-/issues/6310
// - Display filter entry?
// - Add follow, copy & graph actions to context menu.

// Bugs:
// - Slow for large numbers of items.
// - Name resolution doesn't do anything if its preference is disabled.
// - Columns don't resize correctly.
// - Closing the capture file clears conversation data.

// Fixed bugs:
// - Friendly unit displays https://gitlab.com/wireshark/wireshark/-/issues/9231
// - Misleading bps calculation https://gitlab.com/wireshark/wireshark/-/issues/8703
// - Show Absolute time in conversation tables https://gitlab.com/wireshark/wireshark/-/issues/11618
// - The value of 'Rel start' and 'Duration' in "Conversations" no need too precise https://gitlab.com/wireshark/wireshark/-/issues/12803


typedef enum {
    CONV_COLUMN_SRC_ADDR,
    CONV_COLUMN_SRC_PORT,
    CONV_COLUMN_DST_ADDR,
    CONV_COLUMN_DST_PORT,
    CONV_COLUMN_PACKETS,
    CONV_COLUMN_BYTES,
    CONV_COLUMN_PKT_AB,
    CONV_COLUMN_BYTES_AB,
    CONV_COLUMN_PKT_BA,
    CONV_COLUMN_BYTES_BA,
    CONV_COLUMN_START,
    CONV_COLUMN_DURATION,
    CONV_COLUMN_BPS_AB,
    CONV_COLUMN_BPS_BA,
    CONV_NUM_COLUMNS,
    CONV_INDEX_COLUMN = CONV_NUM_COLUMNS
} conversation_column_type_e;

static const QString table_name_ = QObject::tr("Conversation");

static ATapDataModel * createModel(int protoId, QString filter)
{
    return new ConversationDataModel(protoId, filter);
}

static QAbstractItemDelegate * createDelegate(QWidget * parent)
{
    TimelineDelegate * delegate = new TimelineDelegate(parent);
    delegate->setDataRole(ATapDataModel::TIMELINE_DATA);

    return delegate;
}

ConversationDialog::ConversationDialog(QWidget &parent, CaptureFile &cf) :
    TrafficTableDialog(parent, cf, table_name_),
    tcp_graph_requested_(false)
{
    trafficList()->setProtocolInfo(table_name_, &(recent.conversation_tabs));

    trafficTab()->setProtocolInfo(table_name_, trafficList()->protocols(), trafficList()->selectedProtocols(), &createModel);
    trafficTab()->setDelegate(CONV_COLUMN_START, &createDelegate);
    trafficTab()->setDelegate(CONV_COLUMN_DURATION, &createDelegate);
    trafficTab()->setFilter(cf.displayFilter());
    displayFilterCheckBox()->setChecked(cf.displayFilter().length() > 0);
    connect(trafficTab(), &TrafficTab::filterAction, this, &ConversationDialog::filterAction);
    connect(trafficTab()->tabBar(), &QTabBar::currentChanged, this, &ConversationDialog::tabChanged);
    connect(trafficTab(), &TrafficTab::tabDataChanged, this, &ConversationDialog::tabChanged);

    follow_bt_ = buttonBox()->addButton(tr("Follow Stream…"), QDialogButtonBox::ActionRole);
    follow_bt_->setToolTip(tr("Follow a TCP or UDP stream."));
    connect(follow_bt_, SIGNAL(clicked()), this, SLOT(followStream()));

    graph_bt_ = buttonBox()->addButton(tr("Graph…"), QDialogButtonBox::ActionRole);
    graph_bt_->setToolTip(tr("Graph a TCP conversation."));
    connect(graph_bt_, SIGNAL(clicked()), this, SLOT(graphTcp()));

    connect(mainApp->mainWindow(), SIGNAL(displayFilterSuccess(bool)),
            this, SLOT(displayFilterSuccess(bool)));

    absoluteTimeCheckBox()->show();

    updateWidgets();
}

void ConversationDialog::captureFileClosing()
{
    trafficTab()->disableTap();
    displayFilterCheckBox()->setEnabled(false);
    follow_bt_->setEnabled(false);
    graph_bt_->setEnabled(false);
    TrafficTableDialog::captureFileClosing();
}

void ConversationDialog::followStream()
{
    if (file_closed_)
        return;

    int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();
    if (endpointType != ENDPOINT_TCP && endpointType != ENDPOINT_UDP)
        return;

    follow_type_t ftype = FOLLOW_TCP;
    if (endpointType == ENDPOINT_UDP)
        ftype = FOLLOW_UDP;

    int convId = trafficTab()->currentItemData(ATapDataModel::CONVERSATION_ID).toInt();

    // Will set the display filter too.
    // TCP and UDP do not have a "sub-stream", so set a dummy value.
    emit openFollowStreamDialog(ftype, convId, 0);
}

void ConversationDialog::graphTcp()
{
    if (file_closed_)
        return;

    int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();
    if (endpointType != ENDPOINT_TCP)
        return;

    int convId = trafficTab()->currentItemData(ATapDataModel::CONVERSATION_ID).toInt();

    // XXX The GTK+ code opens the TCP Stream dialog. We might want
    // to open the I/O Graphs dialog instead.
    QString filter = QString("tcp.stream eq %1").arg(convId);

    tcp_graph_requested_ = true;
    // Apply the filter for this conversation. When the filter is active, we
    // can draw the TCP graph.
    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void ConversationDialog::tabChanged(int)
{
    bool follow = false;
    bool graph = false;

    if (!file_closed_) {
        int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();
        switch(endpointType) {
            case ENDPOINT_TCP:
                graph = true;
                // Fall through
            case ENDPOINT_UDP:
                follow = true;
                break;
        }
    }

    follow_bt_->setEnabled(follow);
    graph_bt_->setEnabled(graph);

    TrafficTableDialog::currentTabChanged();
}

void ConversationDialog::on_buttonBox_helpRequested()
{
    mainApp->helpTopicAction(HELP_STATS_CONVERSATIONS_DIALOG);
}

void ConversationDialog::displayFilterSuccess(bool success)
{
    if (tcp_graph_requested_) {
        if (success) {
            // The display filter was applied successfully, i.e. the current
            // packet is now part of our selected tcp conversation.
            openTcpStreamGraph(GRAPH_TSEQ_TCPTRACE);
        }
        tcp_graph_requested_ = false;
    }
}

void init_conversation_table(struct register_ct* ct, const char *filter)
{
    mainApp->emitStatCommandSignal("Conversations", filter, GINT_TO_POINTER(get_conversation_proto_id(ct)));
}
