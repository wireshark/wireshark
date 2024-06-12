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
// - Improper wildcard handling https://gitlab.com/wireshark/wireshark/-/issues/8010
// - TShark consolidation https://gitlab.com/wireshark/wireshark/-/issues/6310
// - Display filter entry?
// - Add follow, copy & graph actions to context menu.

// Bugs:
// - Slow for large numbers of items.
// - Name resolution doesn't do anything if its preference is disabled.

// Fixed bugs:
// - Friendly unit displays https://gitlab.com/wireshark/wireshark/-/issues/9231
// - Misleading bps calculation https://gitlab.com/wireshark/wireshark/-/issues/8703
// - Show Absolute time in conversation tables https://gitlab.com/wireshark/wireshark/-/issues/11618
// - The value of 'Rel start' and 'Duration' in "Conversations" no need too precise https://gitlab.com/wireshark/wireshark/-/issues/12803


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

    trafficTab()->setProtocolInfo(table_name_, trafficList(), &(recent.conversation_tabs), &(recent.conversation_tabs_columns), &createModel);
    trafficTab()->setDelegate(&createDelegate);
    trafficTab()->setDelegate(&createDelegate);
    trafficTab()->setFilter(cf.displayFilter());

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

    QVariant protoIdData = trafficTab()->currentItemData(ATapDataModel::PROTO_ID);
    if (protoIdData.isNull())
        return;

    int protoId = protoIdData.toInt();
    if (get_follow_by_proto_id(protoId) == nullptr)
        return;

    int convId = trafficTab()->currentItemData(ATapDataModel::CONVERSATION_ID).toInt();

    // ATapDataModel doesn't support a substream ID (XXX: yet), so set it to a
    // dummy value.
    emit openFollowStreamDialog(protoId, convId, 0);
}

void ConversationDialog::graphTcp()
{
    if (file_closed_)
        return;

    int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();
    if (endpointType != CONVERSATION_TCP)
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
    // By default we'll open the last known opened tab from the Profile
    GList *selected_tab = NULL;

    bool follow = false;
    bool graph = false;

    if (!file_closed_) {
        QVariant proto_id = trafficTab()->currentItemData(ATapDataModel::PROTO_ID);
        if (!proto_id.isNull()) {
            follow = (get_follow_by_proto_id(proto_id.toInt()) != nullptr);

            for (GList * endTab = recent.conversation_tabs; endTab; endTab = endTab->next) {
                int protoId = proto_get_id_by_short_name((const char *)endTab->data);
                if ((protoId > -1) && (protoId==proto_id.toInt())) {
                    selected_tab = endTab;
                }
            }

            // Move the selected tab to the head
            if (selected_tab != nullptr) {
                recent.conversation_tabs = g_list_remove_link(recent.conversation_tabs, selected_tab);
                recent.conversation_tabs = g_list_prepend(recent.conversation_tabs, selected_tab->data);
            }
        }
        int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();
        switch(endpointType) {
            case CONVERSATION_TCP:
                graph = true;
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
