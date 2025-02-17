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

#include <ui/qt/main_window.h>
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
    connect(follow_bt_, &QPushButton::clicked, this, &ConversationDialog::followStream);

    graph_bt_ = buttonBox()->addButton(tr("Graph…"), QDialogButtonBox::ActionRole);
    graph_bt_->setToolTip(tr("Graph a TCP conversation."));
    connect(graph_bt_, &QPushButton::clicked, this, &ConversationDialog::graphTcp);

    iograph_bt_ = buttonBox()->addButton(tr("I/O Graphs"), QDialogButtonBox::ActionRole);
    iograph_bt_->setToolTip(tr("I/OGraph TCP conversations."));
    connect(iograph_bt_, SIGNAL(clicked()), this, SLOT(showGraphIO()));

    connect(mainApp->mainWindow(), &MainWindow::displayFilterSuccess, this, &ConversationDialog::displayFilterSuccess);

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

    // This is null if there's no items for the current tab, but there's no
    // stream to follow in that case.
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
    QString filter = QStringLiteral("tcp.stream eq %1").arg(convId);

    tcp_graph_requested_ = true;
    // Apply the filter for this conversation. When the filter is active, we
    // can draw the TCP graph.
    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void ConversationDialog::showGraphIO()
{
    int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();

    /* get protoId from its corresponding proto shortname
     *
     * XXX - we could directly get this value from a stored value at the
     * conversation level, but doing it here is a good compromise (lower memory
     * consumption, lesser function calls)
     */
    int protoId;
    switch(endpointType) {
        case CONVERSATION_TCP:
            protoId = proto_get_id_by_short_name("TCP");
            break;
        case CONVERSATION_UDP:
            protoId = proto_get_id_by_short_name("UDP");
            break;
        case CONVERSATION_IP:
            protoId = proto_get_id_by_short_name("IPv4");
            break;
        case CONVERSATION_IPV6:
            protoId = proto_get_id_by_short_name("IPv6");
            break;
        case CONVERSATION_ETH:
            protoId = proto_get_id_by_short_name("Ethernet");
            break;
        default:
            return;
            break;
    }

    QVector<uint> typed_conv_ids;
    QVector<QVariant> agg_conv_filters;

    /* First element of the list is the protoId, */
    typed_conv_ids.append(protoId);
    agg_conv_filters.append(protoId);

    QList<QList<QVariant>> lst_ids = trafficTab()->selectedItemsIOGData();

    /* and it is followed by all selected conversations IDs,
     * for both id based list, and aggregated list
     * If no conversation is selected, just go ahead with the
     * default dialog. */

    if(lst_ids.size()>0) {
        // id based list
        QList<QVariant> lst_vars = lst_ids.at(0);
        for (qsizetype i = 1; i < lst_vars.size(); ++i) {
            typed_conv_ids.append(lst_vars[i].toInt());
        }

        // aggregated based list
        lst_vars = lst_ids.at(1);
        for (qsizetype i = 1; i < lst_vars.size(); ++i) {
            agg_conv_filters.append(lst_vars[i]);
        }
    }

    /* Trigger the I/O Graph window opening by emitting the signal with the necessary information:
     *   whether the Filter Display is to be applied for a graph
     *   the QVector containting the TCP selected conversations IDs
     */
    emit openIOGraph(this->displayFilterCheckBox()->isChecked(), typed_conv_ids, agg_conv_filters);
}

void ConversationDialog::tabChanged(int)
{
    // By default we'll open the last known opened tab from the Profile
    GList *selected_tab = NULL;

    bool follow = false;
    bool graph = false;
    bool iograph = false;

    if (!file_closed_) {
        QVariant current_tab_var = trafficTab()->tabBar()->tabData(trafficTab()->currentIndex());
        if (!current_tab_var.isNull()) {
            TabData current_tab_data = qvariant_cast<TabData>(current_tab_var);
            follow = (get_follow_by_proto_id(current_tab_data.protoId()) != nullptr);

            for (GList * endTab = recent.conversation_tabs; endTab; endTab = endTab->next) {
                int protoId = proto_get_id_by_short_name((const char *)endTab->data);
                if ((protoId > -1) && (protoId==current_tab_data.protoId())) {
                    selected_tab = endTab;
                }
            }

            // Move the selected tab to the head
            if (selected_tab != nullptr) {
                recent.conversation_tabs = g_list_remove_link(recent.conversation_tabs, selected_tab);
#if GLIB_CHECK_VERSION(2, 62, 0)
                recent.conversation_tabs = g_list_insert_before_link(recent.conversation_tabs, recent.conversation_tabs, selected_tab);
#else
                recent.conversation_tabs = g_list_prepend(recent.conversation_tabs, selected_tab->data);
                g_list_free_1(selected_tab);
#endif
            }
        }
        int endpointType = trafficTab()->currentItemData(ATapDataModel::ENDPOINT_DATATYPE).toInt();

        /* endpoints allowing I/O Graph */
        switch(endpointType) {
            case CONVERSATION_TCP:
            case CONVERSATION_UDP:
            case CONVERSATION_IP:
            case CONVERSATION_IPV6:
            case CONVERSATION_ETH:
                iograph = true;
                qlonglong selectedCount = trafficTab()->countSelectedItems(ATapDataModel::ENDPOINT_DATATYPE);
                if(selectedCount>1) {
                    follow = false;
                }
                else {
                    graph = true;
                }
                break;
        }
    }

    follow_bt_->setEnabled(follow);
    graph_bt_->setEnabled(graph);
    iograph_bt_->setEnabled(iograph);

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
